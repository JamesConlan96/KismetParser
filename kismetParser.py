#!/usr/bin/env python


import argparse
from datetime import datetime
import json
import logging
from pathlib import Path
import sys
from tabulate import tabulate, tabulate_formats


logger = logging.getLogger(__name__)


class KismetParser():
    """Kismet parser object"""

    def __init__(self) -> None:
        """Initialises a Kismet parser object"""
        self.devices = []
        self.bluetoothDevices = {}
        self.wirelessAps = {}
        self.wirelessClients = {}
        logger.debug("Kismet parser initialised")

    def _epochToDatetime(self, epoch: int) -> str:
        """Converts and epoch value to a readable datetime string
        @param epoch: Epoch value to convert
        @return: Readable datetime string
        """
        return datetime.fromtimestamp(epoch).strftime('%Y-%m-%d %H:%M:%S')

    def _processBluetooth(self, device: dict) -> None:
        """Processes data on a bluetooth device
        @param device: Dictionary containing device data to process
        """
        try:
            mac = str(device['kismet_device_base_macaddr']).upper()
            firstTime = int(device['kismet_device_base_first_time'])
            lastTime = int(device['kismet_device_base_last_time'])
            manufacturer = str(device['kismet_device_base_manuf'])
            name = str(device['kismet_device_base_name'])
        except:
            logger.warning("Invalid bluetooth device record specified")
            return
        rssi = 5000
        if not mac or mac is None:
            logger.warning("Device without MAC address detected")
            return
        if not manufacturer or manufacturer is None:
            manufacturer = "Unknown"
        if not name or name is None:
            name = "Unknown"
        if mac in self.bluetoothDevices.keys():
            new = self.bluetoothDevices[mac]
            new['firstTime'] = min(firstTime, new['firstTime'])
            new['lastTime'] = max(lastTime, new['lastTime'])
            if manufacturer != new['manufacturer'] or name != new['name']:
                logger.warning(f"Conflicting information for {mac}")
            self.bluetoothDevices[mac] = new
        else:
            self.bluetoothDevices[mac] = {
                "firstTime": firstTime,
                "lastTime": lastTime,
                "manufacturer": manufacturer,
                "name": name,
                "rssi": rssi
            }
    
    def _processWirelessAp(self, device: dict) -> None:
        """Processes data on a wireless access point device
        @param device: Dictionary containing device data to process
        """
        try:
            mac = str(device['kismet_device_base_macaddr']).upper()
            firstTime = int(device['kismet_device_base_first_time'])
            lastTime = int(device['kismet_device_base_last_time'])
            manufacturer = str(device['kismet_device_base_manuf'])
            channel = int(device['kismet_device_base_channel'])
            auth = str(device['kismet_device_base_crypt'])
            essid = str(device['dot11_device'][
                        'dot11.device.last_beaconed_ssid_record'][
                        'dot11.advertisedssid.ssid'])
        except:
            logger.warning("Invalid wireless access point device record " +
                           "specified")
            return
        try:
            if str(device['kismet_device_base_signal'][
                          'kismet.common.signal.type']).lower() == "none":
                rssi = 5000
            else:
                rssi = int(device['kismet_device_base_signal'][
                                             'kismet.common.signal.max_signal'])
        except:
            rssi = 5000
        if not mac or mac is None:
            logger.warning("Device without MAC address detected")
            return
        if not manufacturer or manufacturer is None:
            manufacturer = "Unknown"
        if not auth or auth is None:
            auth = "Unknown"
        if not essid or essid is None:
            essid = "Unknown SSID"
        if mac in self.wirelessAps.keys():
            new = self.wirelessAps[mac]
            new['firstTime'] = min(firstTime, new['firstTime'])
            new['lastTime'] = max(lastTime, new['lastTime'])
            new['rssi'] = rssi if abs(rssi) < abs(new['rssi']) else new['rssi']
            if manufacturer != new['manufacturer'] or essid != new['essid'] or \
                channel != new['channel'] or auth != new['auth']:
                logger.warning(f"Conflicting information for {mac}")
            self.wirelessAps[mac] = new
        else:
            self.wirelessAps[mac] = {
                "firstTime": firstTime,
                "lastTime": lastTime,
                "manufacturer": manufacturer,
                "channel": channel,
                "auth": auth,
                "essid": essid,
                "rssi": rssi
            }

    def _processWirelessClient(self, device: dict) -> None:
        """Processes data on a wireless client device
        @param device: Dictionary containing device data to process
        """
        try:
            mac = str(device['kismet_device_base_macaddr']).upper()
            firstTime = int(device['kismet_device_base_first_time'])
            lastTime = int(device['kismet_device_base_last_time'])
            manufacturer = str(device['kismet_device_base_manuf'])
            bssid = str(device['dot11_device']['dot11.device.last_bssid'])
            probedSsids = []
            if "dot11.device.last_probed_ssid_record" in device['dot11_device'
                                                                ].keys():
                if device['dot11_device'][
                                        'dot11.device.last_probed_ssid_record'][
                                        'dot11.probedssid.ssid']:
                    probedSsids.append(str(device['dot11_device'][
                                        'dot11.device.last_probed_ssid_record'][
                                        'dot11.probedssid.ssid']))
                else:
                    probedSsids.append("Unknown SSID")
        except:
            logger.warning("Invalid wireless client device record specified")
            return
        try:
            if str(device['kismet_device_base_signal'][
                          'kismet.common.signal.type']).lower() == "none":
                rssi = 5000
            else:
                rssi = int(device['kismet_device_base_signal'][
                                             'kismet.common.signal.max_signal'])
        except:
            rssi = 5000
        if not mac or mac is None:
            logger.warning("Device without MAC address detected")
            return
        if not manufacturer or manufacturer is None:
            manufacturer = "Unknown"
        if not bssid or bssid is None:
            bssid = "Unknown"
        if mac in self.wirelessClients.keys():
            new = self.wirelessClients[mac]
            new['firstTime'] = min(firstTime, new['firstTime'])
            new['lastTime'] = max(lastTime, new['lastTime'])
            new['probedSsids'] = list(set(probedSsids + new['probedSsids']))
            new['rssi'] = rssi if abs(rssi) < abs(new['rssi']) else new['rssi']
            if manufacturer != new['manufacturer'] or bssid != new['bssid']:
                logger.warning(f"Conflicting information for {mac}")
            self.wirelessClients[mac] = new
        else:
            self.wirelessClients[mac] = {
                "firstTime": firstTime,
                "lastTime": lastTime,
                "manufacturer": manufacturer,
                "bssid": bssid,
                "probedSsids": probedSsids,
                "rssi": rssi
            }

    def _reportBluetooth(self, outputDir: Path, filePrefix: str, format: str,
                         overwrite: bool) -> None:
        """Reports on bluetooth devices
        @param outputDir: Directory to save output files to
        @param filePrefix: Prefix to apply to output file names
        @param format: Python-tabulate format for output tables
        @param overwrite: Whether or not to overwrite existing files without 
        prompting the user
        """
        if not self.bluetoothDevices:
            logger.warning("No bluetooth devices to report on")
            return
        logger.debug("Reporting on bluetooth devices")
        outFile = outputDir.joinpath(f"{filePrefix}bluetooth_devices.txt")
        if outFile.exists() and not overwrite and not \
            self._yesNo(f"output file '{outFile}' exists, overwrite it?"):
            return
        try:
            with outFile.open('w') as f:
                headings = ["MAC Address", "First Time", "Last Time",
                            "Manufacturer", "Common Name", "RSSI"]
                rows = []
                for mac in self.bluetoothDevices.keys():
                    row = [mac]
                    row.append(self._epochToDatetime(self.bluetoothDevices[mac][
                                                                  'firstTime']))
                    row.append(self._epochToDatetime(self.bluetoothDevices[mac][
                                                                   'lastTime']))
                    row.append(self.bluetoothDevices[mac]['manufacturer'])
                    row.append(self.bluetoothDevices[mac]['name'])
                    if abs(self.bluetoothDevices[mac]['rssi']) > 255:
                        row.append("Unknown")
                    else:
                        row.append(self.bluetoothDevices[mac]['rssi'])
                    rows.append(row)
                rows.sort(key=lambda x: f"{x[-1]} {x[0]}")
                f.write(tabulate(rows, headings, format))
        except:
            error = f"Could not write to output file '{outFile}'"
            logger.error(error)
            raise Warning(error)
        logger.debug(f"Bluetooth report written to '{outFile}'")

    def _reportWirelessAps(self, outputDir: Path, filePrefix: str, format: str,
                           overwrite: bool) -> None:
        """Reports on wireless access point devices
        @param outputDir: Directory to save output files to
        @param filePrefix: Prefix to apply to output file names
        @param format: Python-tabulate format for output tables
        @param overwrite: Whether or not to overwrite existing files without 
        prompting the user
        """
        if not self.wirelessAps:
            logger.warning("No wireless access point devices to report on")
            return
        logger.debug("Reporting on wireless access point devices")
        outFile = outputDir.joinpath(f"{filePrefix}wireless_ap_devices.txt")
        if outFile.exists() and not overwrite and not \
            self._yesNo(f"output file '{outFile}' exists, overwrite it?"):
            return
        try:
            with outFile.open('w') as f:
                headings = ["MAC Address", "First Time", "Last Time",
                            "Manufacturer", "Channel", "Authentication",
                            "ESSID", "RSSI"]
                rows = []
                for mac in self.wirelessAps.keys():
                    row = [mac]
                    row.append(self._epochToDatetime(self.wirelessAps[mac][
                                                                  'firstTime']))
                    row.append(self._epochToDatetime(self.wirelessAps[mac][
                                                                   'lastTime']))
                    row.append(self.wirelessAps[mac]['manufacturer'])
                    row.append(self.wirelessAps[mac]['channel'])
                    row.append(self.wirelessAps[mac]['auth'])
                    row.append(self.wirelessAps[mac]['essid'])
                    if abs(self.wirelessAps[mac]['rssi']) > 255:
                        row.append("Unknown")
                    else:
                        row.append(self.wirelessAps[mac]['rssi'])
                    rows.append(row)
                rows.sort(key=lambda x: f"{x[-1]} {x[0]}")
                f.write(tabulate(rows, headings, format))
        except:
            error = f"Could not write to output file '{outFile}'"
            logger.error(error)
            raise Warning(error)
        logger.debug(f"Wireless access point report written to '{outFile}'")

    def _reportWirelessClients(self, outputDir: Path, filePrefix: str,
                               format: str, overwrite: bool) -> None:
        """Reports on wireless client devices
        @param outputDir: Directory to save output files to
        @param filePrefix: Prefix to apply to output file names
        @param format: Python-tabulate format for output tables
        @param overwrite: Whether or not to overwrite existing files without 
        prompting the user
        """
        if not self.wirelessClients:
            logger.warning("No wireless client devices to report on")
            return
        logger.debug("Reporting on wireless client devices")
        outFile = outputDir.joinpath(f"{filePrefix}wireless_client_devices.txt")
        if outFile.exists() and not overwrite and not \
            self._yesNo(f"output file '{outFile}' exists, overwrite it?"):
            return
        try:
            with outFile.open('w') as f:
                headings = ["MAC Address", "First Time", "Last Time",
                            "Manufacturer", "BSSID", "Probed SSIDs", "RSSI"]
                rows = []
                for mac in self.wirelessClients.keys():
                    row = [mac]
                    row.append(self._epochToDatetime(self.wirelessClients[mac][
                                                                  'firstTime']))
                    row.append(self._epochToDatetime(self.wirelessClients[mac][
                                                                   'lastTime']))
                    row.append(self.wirelessClients[mac]['manufacturer'])
                    row.append(self.wirelessClients[mac]['bssid'])
                    row.append(', '.join(self.wirelessClients[mac][
                                                                'probedSsids']))
                    if abs(self.wirelessClients[mac]['rssi']) > 255:
                        row.append("Unknown")
                    else:
                        row.append(self.wirelessClients[mac]['rssi'])
                    rows.append(row)
                rows.sort(key=lambda x: f"{x[-1]} {x[0]}")
                f.write(tabulate(rows, headings, format))
        except:
            error = f"Could not write to output file '{outFile}'"
            logger.error(error)
            raise Warning(error)
        logger.debug(f"Wireless client report written to '{outFile}'")
    
    def _yesNo(self, prompt: str) -> bool:
        """Prompts the user for a yes/no response
        @param prompt: Prompt to display to the user
        @return: True if yes, False if no
        """
        yn = input(f"{prompt} (y/n): ")
        if yn.lower() == 'y':
            return True
        elif yn.lower() == 'n':
            return False
        else:
            return self._yesNo(prompt)
    
    def addFile(self, file: Path) -> None:
        """Adds an input file to the parser
        @param file: File to add
        """
        file = file.resolve()
        if not file.exists():
            error = f"Input file '{file}' does not exist"
            logger.error(error)
            raise Warning(error)
        try:
            with file.open() as f:
                lines = f.readlines()
        except:
            error = f"Could not read input file '{file}'"
            logger.error(error)
            raise Warning(error)
        for line in lines:
            if line.strip():
                try:
                    self.devices.append(json.loads(line))
                except:
                    error = f"Input file '{file}' is not a valid EKJSON file"
                    logger.error(error)
                    raise Warning(error)
        logger.debug(f"Input file '{file}' added successfully")
    
    def parse(self) -> None:
        """Parses data from input files"""
        logger.debug("Initiated parsing of device data")
        for device in self.devices:
            match device['kismet_device_base_type']:
                case "BTLE":
                    self._processBluetooth(device)
                case "Wi-Fi AP":
                    self._processWirelessAp(device)
                case "Wi-Fi Client":
                    self._processWirelessClient(device)
                case _:
                    logger.warning("Device of unrecognised type '" +
                                   device['kismet_device_base_type'] +
                                   "' detected")
                    continue
        logger.debug("Parsing complete")
    
    def report(self, outputDir: Path = Path("."), filePrefix: str = "",
               format: str = "github", overwrite: bool = False) -> None:
        """Generates ouput files
        @param outputDir: Directory to save output files to
        @param filePrefix: Prefix to apply to output file names
        @param format: Python-tabulate format for output tables
        @param overwrite: Whether or not to overwrite existing files without 
        prompting the user
        """
        logger.debug("Initiated reporting")
        try:
            outputDir = outputDir.resolve()
            outputDir.mkdir(parents=True, exist_ok=True)
        except:
            error = f"Could not create output directory '{outputDir}'"
            logger.error(error)
            raise Warning(error)
        self._reportBluetooth(outputDir, filePrefix, format, overwrite)
        self._reportWirelessAps(outputDir, filePrefix, format, overwrite)
        self._reportWirelessClients(outputDir, filePrefix, format, overwrite)
        logger.debug("Reporting complete")

    def summarise(self) -> str:
        """Generates a summary of findings
        @return Summary of findings
        """
        return tabulate([
            ["Total bluetooth devices identified:", len(self.bluetoothDevices)],
            ["Total wireless access points identified:", len(self.wirelessAps)],
            ["Total wireless clients identified:", len(self.wirelessClients)]
        ], tablefmt="plain")
            

def genArgParser() -> argparse.ArgumentParser:
    """Generates a CLI argument parser
    @return: CLI argument parser object
    """
    parser = argparse.ArgumentParser(description="A parser for Kismet EKJSON " +
                                     "output generated using " +
                                     "kismetdb_dump_devices")
    parser.add_argument('-d', '--outputDir', type=Path, action="store",
                        help="directory to save output files to (Default: " +
                        "./kismetParser)", default="./kismetParser",
                        metavar="DIRECTORY")
    parser.add_argument('-f', '--format', choices=tabulate_formats,
                        help="format for output tables (default: github)",
                        default="github")
    parser.add_argument('-i', '--inputFiles', nargs='+', type=Path,
                        action="store", required=True, metavar="FILE",
                        help="EKJSON files to parse")
    parser.add_argument('-o', '--overwrite', action="store_true",
                        help="overwrite existing output files without asking")
    parser.add_argument('-p', '--outputPrefix', action="store",
                        help="prefix to apply to output file names",
                        metavar="PREFIX", default="")
    return parser

def main() -> None:
    """Main method"""
    if len(sys.argv) == 1:
        genArgParser().print_usage()
        sys.exit()
    try:
        logHandlerStdout = logging.StreamHandler(sys.stdout)
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(asctime)s - %(levelname)-7s - " +
                    "%(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
            handlers=[logHandlerStdout]
        )
        args = genArgParser().parse_args()
        kp = KismetParser()
        for file in args.inputFiles:
            kp.addFile(file)
        kp.parse()
        kp.report(args.outputDir, args.outputPrefix, args.format,
                  args.overwrite)
        print("\nParsing complete!\n", kp.summarise(), "", sep="\n")
    except Warning:
        sys.exit()
    except SystemExit:
        logger.debug("Terminated by user")
        sys.exit()


if __name__ == "__main__":
    main()
