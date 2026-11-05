"""Shared gkbus connection construction and resource cleanup."""

from gkbus.device import Bus
from gkbus.protocol import kwp2000
from gkbus.transport import Kwp2000OverCanTransport, Kwp2000OverKLineTransport

from .utils import log


def open_connection(device, bus_type, config):
    """Open the channel separately so RSW/MTOS can reuse it after KWP closes."""
    try:
        if bus_type == Bus.CANBUS:
            channel = device.canbus(config['bitrate'])
            transport_type = Kwp2000OverCanTransport
        else:
            channel = device.kline()
            transport_type = Kwp2000OverKLineTransport
        transport = transport_type(channel, tx_id=config['tx_id'], rx_id=config['rx_id'])
        channel.open()
        return kwp2000.Kwp2000Protocol(transport)
    except BaseException:
        device.close()
        raise


def close_connection(bus, device, log_callback=None):
    """Attempt both closes even when one resource reports an error."""
    success = True
    for resource in (bus, device):
        if resource is None:
            continue
        try:
            resource.close()
        except Exception as exc:
            success = False
            log('[!] Could not close interface: {}'.format(exc), log_callback)
    return success
