from scapy.all import rdpcap


def _read_pcap(pcap_loc):
    return rdpcap(pcap_loc)


def get_tcp_packets_fields(pcap_location=None):
    """
    Get all of the TCP fields dicts from the PCAP that is being read in

    pcap_location - (str) path to PCAP location
    """
    if pcap_location is None:
        raise AttributeError('PCAP Location has not been set properly')

    packets = _read_pcap(pcap_location)
    packets_list = []
    try:
        for p in packets:
            if 'TCP' in p:
                p['TCP'].fields['tcp_payload'] = len(p['TCP'].payload)
                packets_list.append(p['TCP'].fields)
        return packets_list
    except AttributeError:
        print('Layer does not have fields')
        return packets_list


def _build_keyword_args(fields_dict):
    return {'prev_sport_seq': fields_dict['seq'],
            'prev_sport': fields_dict['sport'],
            'prev_payload_len': fields_dict['tcp_payload'],
            'prev_flags': fields_dict['flags']}


def _sanity_check_seq_ack(tcp_flow_fields, **kwargs):
    if len(tcp_flow_fields) is 0:
        return True

    fields_dict = tcp_flow_fields[0]
    if not kwargs:
        # First iteration, no comparisons to be made
        return _sanity_check_seq_ack(tcp_flow_fields[1:],
                                     **_build_keyword_args(fields_dict))

    if fields_dict['sport'] is kwargs['prev_sport']:
        # No change in direction, no SEQ / ACK comparison to be made
        return _sanity_check_seq_ack(tcp_flow_fields[1:],
                                     **_build_keyword_args(fields_dict))

    if kwargs['prev_flags'] != 16 and kwargs['prev_payload_len'] == 0:
        # No payload, but more than just Ack flag set for packet
        if fields_dict['ack'] == (1 + kwargs['prev_sport_seq']):
            return _sanity_check_seq_ack(tcp_flow_fields[1:],
                                         **_build_keyword_args(fields_dict))
        else:
            return False
    elif kwargs['prev_flags'] == 16 and kwargs['prev_payload_len'] == 0:
        # Ack flag only, no change in seq or ack values
        return _sanity_check_seq_ack(tcp_flow_fields[1:],
                                     **_build_keyword_args(fields_dict))
    else:
        # Current Ack should equal previous payload size plus previous seq
        if fields_dict['ack'] == (kwargs['prev_payload_len'] +
                                  kwargs['prev_sport_seq']):
            return _sanity_check_seq_ack(tcp_flow_fields[1:],
                                         **_build_keyword_args(fields_dict))
        else:
            return False


def has_handshakes(tcp_flow_fields):
    return (_has_initial_handshake(tcp_flow_fields) and
            _has_final_handshake(tcp_flow_fields))


def _has_initial_handshake(tcp_flow_fields, **kwargs):
    # Binary representation of TCP Flags
    syn = 0b0000000010
    ack = 0b0000010000

    if not kwargs:
        kwargs = {'packets_sought': 0b00,
                  'first_packet': 0b001,
                  'second_packet': 0b010,
                  'third_packet': 0b100,
                  'all_seen': 0b111,
                  'already_seen': 0b000}
    elif kwargs['already_seen'] & kwargs['all_seen']:
        return True
    elif (len(tcp_flow_fields) is 0 and
            not (kwargs['already_seen'] & kwargs['all_seen'])):
        return False
    elif kwargs['already_seen'] & 0b0:
        # Find Initiator's request for TCP Handshake
        if syn & tcp_flow_fields[0].flags:
            kwargs['initiators_port'] = tcp_flow_fields['sport']
            kwargs['responders_port'] = tcp_flow_fields['dport']
            kwargs['already_seen'] += kwargs['first_packet']
        return _has_initial_handshake(tcp_flow_fields[1:], **kwargs)
    elif kwargs['already_seen'] & kwargs['first_packet']:
        # Initial TCP Request already seen, look for response
        if ((syn + ack) & tcp_flow_fields[0].flags and
                kwargs['initiators_port'] == tcp_flow_fields[0].dport and
                kwargs['responders_port'] == tcp_flow_fields[0].sport):
            kwargs['already_seen'] += kwargs['second_packet']
        return _has_initial_handshake(tcp_flow_fields[1:], **kwargs)
    elif (kwargs['already_seen'] &
            (kwargs['first_packet'] + kwargs['second_packet'])):
        if (ack & tcp_flow_fields[0].flags and
                kwargs['initiators_port'] == tcp_flow_fields[0].sport and
                kwargs['responders_port'] == tcp_flow_fields[0].dport):
            kwargs['already_seen'] += kwargs['third_packet']
            return True
        return _has_initial_handshake(tcp_flow_fields[1:], **kwargs)


def _has_final_handshake(tcp_flow_fields):
    fin = 0x01
    for packet in tcp_flow_fields:
        if fin & packet['flags']:
            # TODO start looking for rest of handshake
            print('BANG : FIN')


def get_tcp_flow_fields(tcp_packets):
    """
    Return a list of dicts with only the ack, dport, sport and seq fields.

    tcp_packets - (list) List of dicts of all TCP fields per packet
    """
    ignore_fields = {'chksum', 'dataofs', 'options', 'reserved', 'urgptr',
                     'window'}
    return [{d: tcp_dict[d] for d in tcp_dict if d not in ignore_fields}
            for tcp_dict in tcp_packets]


if __name__ == '__main__':
    import os
    import sys
    try:
        PCAP_LOCATION = sys.argv[1]
        if not os.path.isfile(PCAP_LOCATION):
            sys.exit('Path not valid')
    except IndexError:
        sys.exit('Need to pass in path to PCAP')

    print(_sanity_check_seq_ack(
        get_tcp_flow_fields(
            get_tcp_packets_fields(PCAP_LOCATION))))
