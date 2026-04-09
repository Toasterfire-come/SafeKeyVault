#!/usr/bin/env python3
"""Generate STM32U5_Custom_Board.svj and ERC report from board_spec.json."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple


ROOT = Path(__file__).resolve().parents[1]
SPEC_PATH = ROOT / "board_spec.json"
SVJ_PATH = ROOT / "STM32U5_Custom_Board.svj"
ERC_JSON_PATH = ROOT / "STM32U5_Custom_Board_erc.json"
ERC_TXT_PATH = ROOT / "STM32U5_Custom_Board_erc.txt"


# STM32U5 generic LQFP-64 style mapping placeholder used by board scaffold.
STM32U5_PIN_NUMBERS: Dict[str, int] = {
    "3V3_1": 1,
    "3V3_2": 19,
    "3V3_3": 32,
    "GND_1": 18,
    "GND_2": 31,
    "USB_DP": 45,
    "USB_DM": 44,
    "XIN": 8,
    "XOUT": 9,
    "PA0": 10,
    "PA1": 11,
    "PB8": 61,
    "PB9": 62,
    "PB5": 57,
    "PA6": 22,
    "PA7": 23,
    "PA5": 21,
    "PA4": 20,
    "SWDIO": 46,
    "SWCLK": 49,
}


FOOTPRINTS: Dict[str, str] = {
    "USB_C": "Connector_USB:USB_C_Receptacle_HRO_TYPE-C-31-M-12",
    "Resistor": "Resistor_SMD:R_0603_1608Metric",
    "AMS1117-3.3": "Package_TO_SOT_SMD:SOT-223-3_TabPin2",
    "Capacitor": "Capacitor_SMD:C_0603_1608Metric",
    "STM32U5": "Package_QFP:LQFP-64_10x10mm_P0.5mm",
    "W25Q128": "Package_SO:SOIC-8_5.23x5.23mm_P1.27mm",
    "ATECC608A": "Package_SO:SOIC-8_3.9x4.9mm_P1.27mm",
    "Crystal": "Crystal:Crystal_SMD_3225-4Pin_3.2x2.5mm",
    "TTP223": "Package_TO_SOT_SMD:SOT-23-6",
    "LED": "LED_SMD:LED_0603_1608Metric",
    "PushButton": "Button_Switch_SMD:SW_SPST_B3U-1000P",
    "SWD_Header": "Connector_PinHeader_2.54mm:PinHeader_1x03_P2.54mm_Vertical",
}


@dataclass
class ErcIssue:
    severity: str
    rule: str
    message: str


def load_spec(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def build_connection_index(spec: dict) -> Dict[str, List[dict]]:
    net_index: Dict[str, List[dict]] = {}
    for comp in spec["components"]:
        ref = comp["ref"]
        ctype = comp["type"]
        for pin_name, net_name in comp["pins"].items():
            net_index.setdefault(net_name, []).append(
                {"ref": ref, "component_type": ctype, "pin": pin_name}
            )
    return net_index


def build_components(spec: dict) -> List[dict]:
    components: List[dict] = []
    for comp in spec["components"]:
        footprint = FOOTPRINTS.get(comp["type"], "UNSPECIFIED")
        pins: List[dict] = []
        for pin_name, net_name in comp["pins"].items():
            pin_entry = {
                "name": pin_name,
                "number": pin_name,
                "net": net_name,
            }
            if comp["type"] == "STM32U5":
                pin_entry["number"] = STM32U5_PIN_NUMBERS.get(pin_name, "UNKNOWN")
            pins.append(pin_entry)
        components.append(
            {
                "ref": comp["ref"],
                "type": comp["type"],
                "value": comp.get("value", ""),
                "footprint": footprint,
                "pins": pins,
            }
        )
    return components


def build_nets(spec: dict, net_index: Dict[str, List[dict]]) -> List[dict]:
    explicit_nets = [net["name"] for net in spec.get("nets", [])]
    all_nets = sorted(set(explicit_nets) | set(net_index.keys()))
    return [
        {
            "name": net_name,
            "label": net_name,
            "connections": net_index.get(net_name, []),
        }
        for net_name in all_nets
    ]


def build_wires(net_index: Dict[str, List[dict]]) -> List[dict]:
    wires: List[dict] = []
    for net_name, nodes in sorted(net_index.items()):
        if len(nodes) < 2:
            continue
        src = nodes[0]
        for dst in nodes[1:]:
            wires.append(
                {
                    "net": net_name,
                    "from": f"{src['ref']}.{src['pin']}",
                    "to": f"{dst['ref']}.{dst['pin']}",
                }
            )
    return wires


def run_erc(spec: dict, net_index: Dict[str, List[dict]]) -> Tuple[str, List[ErcIssue]]:
    issues: List[ErcIssue] = []
    resistor_pairs = set()

    for comp in spec["components"]:
        if comp["type"] != "Resistor":
            continue
        nets = list(comp["pins"].values())
        if len(nets) == 2 and all(isinstance(net, str) and net for net in nets):
            resistor_pairs.add(frozenset(nets))

    # Rule: every pin must belong to a named net.
    for comp in spec["components"]:
        for pin_name, net_name in comp["pins"].items():
            if not isinstance(net_name, str) or not net_name.strip():
                issues.append(
                    ErcIssue(
                        severity="error",
                        rule="pin_has_net",
                        message=f"{comp['ref']}.{pin_name} is missing a net name",
                    )
                )

    # Rule: standalone nets should be flagged.
    for net_name, nodes in sorted(net_index.items()):
        if len(nodes) < 2:
            issues.append(
                ErcIssue(
                    severity="warning",
                    rule="single_connection_net",
                    message=f"Net {net_name} has only one connection",
                )
            )

    # Rule: critical supply nets should exist.
    for required in ("VBUS", "3V3", "GND", "USB_DP", "USB_DM"):
        if required not in net_index:
            issues.append(
                ErcIssue(
                    severity="error",
                    rule="required_net_missing",
                    message=f"Required net {required} is not present",
                )
            )

    # Rule: USB data lines should include series resistors near STM32U5.
    dp_series_ok = frozenset({"USB_DP", "USB_DP_CONN"}) in resistor_pairs
    dm_series_ok = frozenset({"USB_DM", "USB_DM_CONN"}) in resistor_pairs
    if (
        "USB_DP" in net_index
        and "USB_DM" in net_index
        and not (dp_series_ok and dm_series_ok)
    ):
        issues.append(
            ErcIssue(
                severity="warning",
                rule="usb_series_resistors_recommended",
                message=(
                    "Add 27R series resistors between USB connector D+/D- and STM32U5 "
                    "USB_DP/USB_DM (expected nets USB_DP_CONN/USB_DM_CONN)"
                ),
            )
        )

    # Rule: external QSPI flash path should be complete for STM32U5.
    stm32u5 = next((c for c in spec["components"] if c["type"] == "STM32U5"), None)
    qspi_ok = False
    if stm32u5:
        mcu_pins = stm32u5["pins"]
        required_qspi = {"QSPI_CSN", "QSPI_SCLK", "QSPI_SD0", "QSPI_SD1", "QSPI_SD2", "QSPI_SD3"}
        if required_qspi.issubset(set(mcu_pins.keys())):
            mcu_csn = mcu_pins["QSPI_CSN"]
            mcu_sclk = mcu_pins["QSPI_SCLK"]
            mcu_sd0 = mcu_pins["QSPI_SD0"]
            mcu_sd1 = mcu_pins["QSPI_SD1"]
            mcu_sd2 = mcu_pins["QSPI_SD2"]
            mcu_sd3 = mcu_pins["QSPI_SD3"]

            flashes = [c for c in spec["components"] if c["type"] == "W25Q128"]
            for flash in flashes:
                fp = flash["pins"]
                required_fp = {"CS", "CLK", "DI", "DO", "WP", "HOLD"}
                if not required_fp.issubset(set(fp.keys())):
                    continue
                cs_ok = fp["CS"] == mcu_csn
                if (
                    cs_ok
                    and fp["CLK"] == mcu_sclk
                    and fp["DI"] == mcu_sd0
                    and fp["DO"] == mcu_sd1
                    and fp["WP"] == mcu_sd2
                    and fp["HOLD"] == mcu_sd3
                ):
                    qspi_ok = True
                    break

    if not qspi_ok:
        issues.append(
            ErcIssue(
                severity="warning",
                rule="stm32u5_qspi_flash_required",
                message=(
                    "STM32U5 QSPI flash path incomplete: add W25Q128 with "
                    "CS/CLK/DI/DO/WP/HOLD to QSPI_CSN/QSPI_SCLK/QSPI_SD0/"
                    "QSPI_SD1/QSPI_SD2/QSPI_SD3"
                ),
            )
        )

    status = "PASS" if not any(issue.severity == "error" for issue in issues) else "FAIL"
    return status, issues


def main() -> None:
    spec = load_spec(SPEC_PATH)
    net_index = build_connection_index(spec)

    svj = {
        "project": spec["project"],
        "format": "svj-1.0",
        "source": str(SPEC_PATH.name),
        "components": build_components(spec),
        "nets": build_nets(spec, net_index),
        "wire_connections": build_wires(net_index),
        "net_labels": sorted(net_index.keys()),
        "metadata": {
            "notes": [
                "Full connectivity generated from logical net assignments.",
                "STM32U5 pin numbers are mapped for an LQFP-64 package scaffold.",
                "Footprints are assigned as KiCad-compatible library identifiers.",
                "ERC verifies USB series resistors and complete STM32U5 QSPI flash wiring.",
            ]
        },
    }

    status, issues = run_erc(spec, net_index)
    erc = {
        "project": spec["project"],
        "status": status,
        "errors": [issue.__dict__ for issue in issues if issue.severity == "error"],
        "warnings": [issue.__dict__ for issue in issues if issue.severity == "warning"],
    }

    SVJ_PATH.write_text(json.dumps(svj, indent=2) + "\n", encoding="utf-8")
    ERC_JSON_PATH.write_text(json.dumps(erc, indent=2) + "\n", encoding="utf-8")

    report_lines = [
        f"ERC RESULT: {status}",
        f"Errors: {len(erc['errors'])}",
        f"Warnings: {len(erc['warnings'])}",
        "",
        "Warnings:",
    ]
    for warning in erc["warnings"]:
        report_lines.append(f"- [{warning['rule']}] {warning['message']}")
    if not erc["warnings"]:
        report_lines.append("- none")
    if erc["errors"]:
        report_lines.append("")
        report_lines.append("Errors:")
        for error in erc["errors"]:
            report_lines.append(f"- [{error['rule']}] {error['message']}")
    ERC_TXT_PATH.write_text("\n".join(report_lines) + "\n", encoding="utf-8")

    print(f"Wrote: {SVJ_PATH}")
    print(f"Wrote: {ERC_JSON_PATH}")
    print(f"Wrote: {ERC_TXT_PATH}")
    print(f"ERC status: {status}")


if __name__ == "__main__":
    main()
