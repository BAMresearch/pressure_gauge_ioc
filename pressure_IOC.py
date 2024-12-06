import datetime
import logging
import socket
import struct
import sys
import attrs

from caproto import ChannelData
from caproto.server import (
    AsyncLibraryLayer,
    PVGroup,
    pvproperty,
    PvpropertyString,
    run,
    template_arg_parser,
)

def validate_ip_address(instance, attribute, value):
    try:
        socket.inet_aton(value)
    except socket.error:
        raise ValueError(f"Invalid IP host: {value}")

def validate_port_number(instance, attribute, value):
    if not (0 <= value <= 65535):
        raise ValueError(f"Port number must be between 0 and 65535, got {value}")

def decode_return_message(message_received):
    " decodes the pressure readout from the inficon pressure gauge " 
    pressure_read_slice = message_received[9:-2]
    pressure_read_hex_values = [item for item in pressure_read_slice]
    pressure_reading = (
        (pressure_read_hex_values[0] << 24)
        | (pressure_read_hex_values[1] << 16)
        | (pressure_read_hex_values[2] << 8)
        | pressure_read_hex_values[3] << 0
    )

    return pressure_reading / (2**20)


def pressure_read(host, port):
    """
    Communicates with the pressure guage
    """

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        # sock.setblocking(False)

        sock.connect((host, port))
        sock.settimeout(1)

        message = message_generator()

        sock.sendall(message)
        
        try:
            message_received = sock.recv(1024)
            message_verification = check_crc(message_received)
            if not message_verification:
                logging.warning('incorrect CRC for received answer')
                return -1
            else:

                return decode_return_message(message_received)

        except TimeoutError:
            logging.warning('Timeout when waiting for a response from the gauge')
            return -1
            

def check_crc(message):
    """ """
    message_sans_crc = []

    for i in range(len(message) - 2):
        message_sans_crc.append(message[i])

    # crc16_table = crc16_table()

    crc_calc = inficon_crc16(
        message_sans_crc, len(message_sans_crc), inficon_init_crc16_table()
    )

    message_w_crc_calc = struct.pack("<13BH", *message_sans_crc, crc_calc)

    if message_w_crc_calc == message:
        return True
    else:
        return False


def message_generator():
    """
    generates message with crc

    """
    message = []

    message.append(0)
    message.append(0)
    message.append(0)
    message.append(5)
    message.append(1)
    message.append(0)
    message.append(221)
    message.append(0)
    message.append(0)

    message_hex = struct.pack("9B", *message)

    crc = inficon_crc16(message_hex, len(message), inficon_init_crc16_table())

    # crc_1 = (crc >> 8) & 0xFF
    # crc_2 = crc & 0xFF

    # message.append(crc_2) # flipping the high  & low bytes
    # message.append(crc_1)

    message_string = struct.pack("<9BH", *message, crc)

    # for item in message:
    #     message_string += '\\'+ hex(item)[1:]

    return message_string


def inficon_init_crc16_table():
    """
    Code to generate crc16 table
    """

    polynomial = 0x8408
    _inficon_crc16_table = [0] * 256

    for i in range(256):
        value = 0
        temp = i

        for j in range(8):
            if (value ^ temp) & 0x0001:
                value = (value >> 1) ^ polynomial
            else:
                value >>= 1
            temp >>= 1

        _inficon_crc16_table[i] = value & 0xFFFF

    return _inficon_crc16_table


def inficon_crc16(data, length, crc16_table):
    """
    generates the crc16 code

    """
    initial = 0xFFFF
    crc = initial

    for i in range(length):

        crc = (crc16_table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8)) & 0xFFFF

    return crc


@attrs.define
class PressureIOC(PVGroup):
    """
    A group of PVs regarding reading the pressure.
    """

    # IP address of the board
    host: str = attrs.field(default = "172.17.1.14", validator=validate_ip_address, converter=str)

    # Port number for communication
    port: int = attrs.field(default = 4012, validator=validate_port_number, converter=int)


    def __init__(self, *args, **kwargs) -> None:
        for k in list(kwargs.keys()):
            if k in ['host', 'port']:
                setattr(self, k, kwargs.pop(k))

        super().__init__(*args, **kwargs)

    timestamp = pvproperty(
        value=str(datetime.datetime.utcnow().isoformat() + "Z"),
        name="timestamp",
        doc="Timestamp of pressure measurement",
        dtype=PvpropertyString,
    )

    pressure = pvproperty(value=0.0, name="pressure", units="mbar", record='ao')

    @pressure.scan(period=6, use_scan_field=True)
    async def pressure(self, instance: ChannelData, async_lib: AsyncLibraryLayer):
        await self.pressure.write(pressure_read(self.host, self.port))
        await self.timestamp.write(datetime.datetime.utcnow().isoformat() + "Z")


def main(args=None):

    parser, split_args = template_arg_parser(
        default_prefix="pressure:",
        desc="EPICS IOC for Inficon Pressure Gauge PCG550! It outputs the pressure in mbar",
    )

    if args is None:
        args = sys.argv[1:]

    parser.add_argument(
        "--host", required=True, type=str, help="IP address of the host/device"
    )
    parser.add_argument(
        "--port", required=True, type=int, help="Port number of the device"
    )

    args = parser.parse_args()

    logging.info(f"Running pressure gauge IOC using {args=}")

    ioc_options, run_options = split_args(args)

    ioc = PressureIOC(host=args.host, port=args.port, **ioc_options)
    run(ioc.pvdb, **run_options)


if __name__ == "__main__":

    main()
