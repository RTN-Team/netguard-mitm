from netfilterqueue import NetfilterQueue
import socket
from os import system

import scapy.all as scapy
import scapy_http.http
from urllib.parse import urlparse, parse_qs

REQUEST_LOGIN = 0
REQUEST_PROTECT = 1


class NetGuardMITM:

    def __init__(self):
        self.netguard_server_ip = None
        self.login_request_callback = None
        self.protect_request_callback = None
        self.login_response_callback = None
        self.protect_response_callback = None
        self.file_upload_packet_callback = None
        self.file_download_packet_callback = None
        self.file_transfer_in_progress = False
        self.file_transfer_bytes_remaining = 0
        self.__last_request = None

    def packet_callback(self, raw_packet):
        """
        Main call back of sent and received packets.
        :param raw_packet: The packet that is being sent/received.
        """
        packet = scapy.IP(raw_packet.get_payload())

        accept = True

        if packet.haslayer("HTTP"):
            tcp_layer = packet.getlayer("TCP")
            http_layer = packet.getlayer("HTTP")

            if packet.haslayer("Raw") and self.file_transfer_in_progress:
                if packet.dst == self.netguard_server_ip:
                    accept = self.handle_file_upload_packet(raw_packet, packet)
                elif packet.src == self.netguard_server_ip:
                    accept = self.handle_file_download_packet(raw_packet, packet)
                else:
                    accept = True
            if "HTTP Request" in http_layer:
                accept = self.handle_request(raw_packet, packet)
            elif "HTTP Response" in http_layer:
                accept = self.handle_response(raw_packet, packet)

        if accept:
            raw_packet.accept()
        else:
            raw_packet.drop()

    def handle_request(self, raw_packet, packet):
        """
        Handles HTTP requests sent towards netguard.io. All other requests are ignored and therefore accepted.
        :param raw_packet: The raw packet as obtained by NetfilterQueue
        :param packet: The scapy representation of the HTTP packet.
        :return True if the packet should be accepted, False otherwise.
        """
        accept = True

        http_layer = packet.getlayer("HTTP")
        request = http_layer["HTTP Request"]
        if request.Host != b"netguard.io":
            return accept

        # Record the (current) netguard.io IP.
        self.netguard_server_ip = packet.dst

        # Parse URL.
        o = urlparse(request.Path)
        arguments = parse_qs(o.query)

        # Check which API call is being made and invoke corresponding callback.
        if request.Method == b"GET":
            if o.path == b"/API/login.php" and self.login_request_callback:
                self.__last_request = REQUEST_LOGIN
                accept = self.login_request_callback(raw_packet, packet, arguments[b"username"], arguments[b"password"])

        elif request.Method == b"POST":
            if o.path == b"/API/protect.php":
                if self.protect_request_callback:
                    accept = self.protect_request_callback(raw_packet, packet, arguments[b"username"], arguments[b"password"])
                self.__last_request = REQUEST_PROTECT
                self.file_transfer_in_progress = True
                self.file_transfer_bytes_remaining = int(request.fields["Content-Length"])

        return accept

    def handle_response(self, raw_packet, packet):
        """
        Handles a single HTTP response from netguard.io. All other responses are ignored and therefore accepted.
        :param raw_packet: The raw packet as obtained by NetfilterQueue.
        :param packet: The scapy representation of the HTTP packet.
        :return: True if the packet should be accepted, False otherwise.
        """
        accept = True
        if packet.src != self.netguard_server_ip:
            return accept

        http_layer = packet.getlayer("HTTP")
        response = http_layer["HTTP Response"]
        body = packet.getlayer("Raw")

        # NOTE: We assume that the response comes directly after the request.
        # This might not be accurate, as packets can be reordered during the transmission.
        # For more reliable results, check sequence numbers of packets.

        # Check what kind of response we're dealing with.
        if self.__last_request == REQUEST_LOGIN and self.login_response_callback:
            accept = self.login_response_callback(raw_packet, packet, body)
            self.__last_request = None
        elif self.__last_request == REQUEST_PROTECT:
            if self.protect_response_callback:
                accept = self.protect_response_callback(raw_packet, packet, body)

            if "Content-Length" in response.fields:
                self.file_transfer_in_progress = True
                self.file_transfer_bytes_remaining = int(response.fields["Content-Length"])
                self.handle_file_download_packet(raw_packet, packet)
                self.__last_request = None

        return accept

    def handle_file_upload_packet(self, raw_packet, packet):
        """
        Handles a single HTTP packet containing (a chunk of) the file to be uploaded to netguard.io.
        :param raw_packet: The raw packet as obtained by NetfilterQueue.
        :param packet: The scapy representation of the HTTP packet.
        :return: True if the packet should be accepted, False otherwise.
        """
        accept = True

        raw_layer = packet.getlayer("Raw")
        self.file_transfer_bytes_remaining -= len(raw_layer.load)
        if self.file_upload_packet_callback:
            accept = self.file_upload_packet_callback(raw_packet, packet, raw_layer.load, self.file_transfer_bytes_remaining)

        self.file_transfer_in_progress = self.file_transfer_bytes_remaining > 0
        return accept

    def handle_file_download_packet(self, raw_packet, packet):
        """
        Handles a single HTTP packet containing (a chunk of) the protected file that is being downloaded from
        the netguard.io server.
        :param raw_packet: The raw packet as obtained by NetfilterQueue.
        :param packet: THe scapy representation of the HTTP packet.
        :return: True if the packet should be accepted, False otherwise.
        """
        accept = True

        raw_layer = packet.getlayer("Raw")
        self.file_transfer_bytes_remaining -= len(raw_layer.load)
        if self.file_download_packet_callback:
            accept = self.file_download_packet_callback(raw_packet, packet, raw_layer.load, self.file_transfer_bytes_remaining)

        self.file_transfer_in_progress = self.file_transfer_bytes_remaining > 0
        return accept

    def do_mitm(self):
        """
        Performs the man-in-the-middle attack. This function is blocking.
        """

        try:
            # Add necessary IP table entries.
            system("iptables -A INPUT -d 192.168.2.6 -p tcp -j NFQUEUE --queue-num 1")
            system("iptables -A OUTPUT -s 192.168.2.6 -p tcp -j NFQUEUE --queue-num 1")

            # Bind to filter queue.
            nfqueue = NetfilterQueue()
            nfqueue.bind(1, self.packet_callback)
            s = socket.fromfd(nfqueue.get_fd(), socket.AF_UNIX, socket.SOCK_STREAM)

            try:
                nfqueue.run_socket(s)
            except KeyboardInterrupt:
                pass

            s.close()
            nfqueue.unbind()

        finally:
            # Remove IP table entries.
            system("iptables -D INPUT 1")
            system("iptables -D OUTPUT 1")