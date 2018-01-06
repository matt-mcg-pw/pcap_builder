from unittest import main, TestCase

from expects import be_a, be_false, be_true, equal, expect
from scapy.plist import PacketList

import constants_validate_handshakes as constants
import pw_pcap_helper.validate_tcp_flow as vtf


class TestValidateTCPFlow(TestCase):
    def setUp(self):
        self.packets_in_cap_count = 40
        self.test_pcap_file = './junk_data/TCP_example.cap'

    def test_read_pcap_file_len(self):
        expect(len(vtf._read_pcap(self.test_pcap_file))).to(
            equal(self.packets_in_cap_count))

    def test_read_pcap_type(self):
        expect(vtf._read_pcap(self.test_pcap_file)).to(be_a(PacketList))

    def test_get_tcp_packets_fields(self):
        expect(vtf.get_tcp_packets_fields(self.test_pcap_file)).to(
            equal(constants.TCP_RAW_FIELDS))

    def test_get_tcp_flow_fields(self):
        expect(vtf.get_tcp_flow_fields(constants.TCP_RAW_FIELDS)).to(
            equal(constants.TCP_FLOW_DICTS))

    def test_sanity_check_seq_ack(self):
        expect(vtf._sanity_check_seq_ack(constants.TCP_FLOW_DICTS)).to(be_true)

    def test_sanity_check_seq_ack_insane(self):
        expect(vtf._sanity_check_seq_ack(constants.INSANE_TCP_FLOW_DICTS)).to(
            be_false)

    # def test_has_handshakes(self):
    #     expect(True).to(be_false)

    # def test_has_handshakes_false(self):
    #     expect(True).to(be_false)

    # def test_has_initial_handshake(self):
    #     expect(True).to(be_false)

    # def test_has_closing_handshake(self):
    #     expect(True).to(be_false)


if __name__ == "__main__":
    main()
