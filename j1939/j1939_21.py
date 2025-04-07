from .parameter_group_number import ParameterGroupNumber
from .message_id import MessageId
import logging
import time

logger = logging.getLogger(__name__)

class J1939_21:

    class TransferProtocols:
        MAX_TP_PACKET_SIZE = (7 * 0xff)
        MAX_ETP_PACKET_SIZE = (7 * 0x00ffffff)

    class TransferType:
        TP  = 0
        ETP = 1

    class ConnectionMode:
        RTS       = 16
        CTS       = 17
        EOM_ACK   = 19
        BAM       = 32
        ABORT     = 255
        ETP_RTS   = 20
        ETP_CTS   = 21
        ETP_DPO   = 22
        ETP_EOMA  = 23
        ETP_ABORT = ABORT

    class ConnectionAbortReason:
        BUSY = 1        # Already  in  one  or  more  connection  managed  sessions  and  cannot  support another
        RESOURCES = 2   # System  resources  were  needed  for  another  task  so  this  connection  managed session was terminated
        TIMEOUT = 3     # A timeout occured
        # 4..250 Reserved by SAE
        CTS_WHILE_DT = 4  # according AUTOSAR: CTS messages received when data transfer is in progress
        # 251..255 Per J1939/71 definitions - but there are none?

    # Same as ConnectionAbortReason for these cases, but they are not all the same, so establish this precedent
    class ExtendedConnectionAbortReason:
        BUSY           = 1  # Already in one or more connection-managed sessions and cannot support another
        RESOURCES      = 2  # System resources were needed for another task so this connection managed session was terminated
        TIMEOUT        = 3  # A timeout occurred and this is the connection abort to close the session
        CTS_WHILE_DT   = 4  # CTS messages received when data transfer is in progress
        UNEXPECTED_DT  = 6
        UNEXPECTED_DPO = 9

    class Timeout:
        """Timeouts according SAE J1939/21"""
        Tr = 0.200 # Response Time
        Th = 0.500 # Holding Time
        T1 = 0.750
        T2 = 1.250
        T3 = 1.250
        T4 = 1.050
        # timeout for multi packet broadcast messages 50..200ms
        Tb = 0.050

    class SendBufferState:
        WAITING_CTS             = 0 # waiting for CTS
        SENDING_IN_CTS          = 1 # sending packages (temporary state)
        SENDING_BM              = 2 # sending broadcast packages
        TRANSMISSION_FINISHED   = 3 # finished, remove buffer
        WAITING_ETP_DPO         = 4 # got ETP RTS, sent ETP CTS, waiting for ETP DPO
        RECEIVING_ETP_DT        = 5 # got ETP DPO, receiving ETP DTs

    def __init__(self, send_message, job_thread_wakeup, notify_subscribers, max_cmdt_packets, minimum_tp_rts_cts_dt_interval, minimum_tp_bam_dt_interval, ecu_is_message_acceptable):
        # Receive buffers
        self._rcv_buffer = {}
        # Send buffers
        self._snd_buffer = {}

        # List of ControllerApplication
        self._cas = []

        # set minimum time between two tp-rts/cts messages
        self._minimum_tp_rts_cts_dt_interval = minimum_tp_rts_cts_dt_interval

        # set minimum time between two tp-bam messages
        if minimum_tp_bam_dt_interval == None:
            self._minimum_tp_bam_dt_interval = self.Timeout.Tb
        else:
            self._minimum_tp_bam_dt_interval = minimum_tp_bam_dt_interval

        # number of packets that can be sent/received with CMDT (Connection Mode Data Transfer)
        self._max_cmdt_packets = max_cmdt_packets

        self.__job_thread_wakeup = job_thread_wakeup
        self.__send_message = send_message
        self.__notify_subscribers = notify_subscribers
        self.__ecu_is_message_acceptable = ecu_is_message_acceptable

    def add_ca(self, ca):
        self._cas.append(ca)

    def remove_ca(self, device_address):
        for ca in self._cas:
            if device_address == ca._device_address_preferred:
                self._cas.remove(ca)
                return True
        return False

    def _buffer_hash(self, src_address, dest_address):
        """Calcluates a hash value for the given address pair

        :param src_address:
            The Source-Address the connection should bound to.
        :param dest_address:
            The Destination-Address the connection should bound to.

        :return:
            The calculated hash value.

        :rtype: int
        """
        return ((src_address & 0xFF) << 8) | (dest_address & 0xFF)

    def send_pgn(self, data_page, pdu_format, pdu_specific, priority, src_address, dest_address, data, time_limit, frame_format):
        pgn = ParameterGroupNumber(data_page, pdu_format, pdu_specific)
        if len(data) <= 8:
            # send normal message
            mid = MessageId(priority=priority, parameter_group_number=pgn.value, source_address=src_address)
            self.__send_message(mid.can_id, True, data)
        else:
            # Transfer protocol
            if len(data) <= self.TransferProtocols.MAX_TP_PACKET_SIZE:
                transfer_type = self.TransferType.TP
            elif len(data) <= self.TransferProtocols.MAX_ETP_PACKET_SIZE:
                transfer_type = self.TransferType.ETP
            else:
                logger.error("Data size exceeds maximum extended transfer protocol size")
                return False

            # if the PF is between 0 and 239, the message is destination dependent when pdu_specific != 255
            # if the PF is between 240 and 255, the message can only be broadcast
#            if (pdu_specific == ParameterGroupNumber.Address.GLOBAL) or ParameterGroupNumber(0, pdu_format, pdu_specific).is_pdu2_format:
#                dest_address = ParameterGroupNumber.Address.GLOBAL
#            else:
#                dest_address = pdu_specific
            # JBECK I changed this routine so that dest_address is now passed in.
            #       For transport protocol, the PDU format and specific are what we put into the body of the initial RTS message
            #       used to start the transfer.  The destination address is not related to this as the above comments imply (the above
            #       comments may be correct for the broadcast (global) case).  Rather the desination address is independent of the PDU
            #       information.  The PDU information indicates the content type of the transfer (what is this data).  The destination
            #       indicates who this data is being sent to.  (Maybe the original author only did broadcast transfers?)
            #       So, I need to add the destination address to the calling arguments.  I guess it can default to nothing in the non-
            #       transfer protocol case so we don't have to supply it in the user code all the time, although defaulting arguments
            #       is tricky when there is more than one, maybe not in python.

            # init sequence
            # known limitation: only one BAM can be sent in parallel to a destination node
            buffer_hash = self._buffer_hash(src_address, dest_address)
            if buffer_hash in self._snd_buffer:
                # There is already a sequence active for this pair
                return False
            message_size = len(data)
            message_packets = int(message_size / 7) if (message_size % 7 == 0) else int(message_size / 7) + 1

            # if the PF is between 240 and 255, the message can only be broadcast
            if dest_address == ParameterGroupNumber.Address.GLOBAL:
                if transfer_type == self.TransferType.ETP:
                    logger.error("ETP is not supported for broadcast messages")
                    return False
                
                # send BAM
                self.__send_tp_bam(src_address, priority, pgn.value, message_size, message_packets)

                # init new buffer for this connection
                self._snd_buffer[buffer_hash] = {
                        "pgn": pgn.value,
                        "priority": priority,
                        "message_size": message_size,
                        "message_packages": message_packets,
                        "data": data,
                        "state": self.SendBufferState.SENDING_BM,
                        "deadline": time.time() + self._minimum_tp_bam_dt_interval,
                        'src_address' : src_address,
                        'dest_address' : ParameterGroupNumber.Address.GLOBAL,
                        'next_packet_to_send' : 0,
                        'transfer_type' : transfer_type,
                    }
            else:
                # send RTS/CTS
#                pgn.pdu_specific = 0  # this is 0 for peer-to-peer transfer
                # init new buffer for this connection
                self._snd_buffer[buffer_hash] = {
                        "pgn": pgn.value,
                        "priority": priority,
                        "message_size": message_size,
                        "message_packages": message_packets,
                        "data": data,
                        "state": self.SendBufferState.WAITING_CTS,
                        "deadline": time.time() + self.Timeout.T3,
                        'src_address' : src_address,
#                        'dest_address' : pdu_specific,
                        'dest_address' : dest_address,
                        'next_packet_to_send' : 0,
                        'next_wait_on_cts': 0,
                        'transfer_type' : transfer_type
                    }
#                self.__send_tp_rts(src_address, pdu_specific, priority, pgn.value, message_size, num_packets, min(self._max_cmdt_packets, num_packets))
#                print("DEST",dest_address,"PGN VALUE ",hex(pgn.value))
                if transfer_type == self.TransferType.TP:
                    self.__send_tp_rts(src_address, dest_address, priority, pgn.value, message_size, message_packets, min(self._max_cmdt_packets, message_packets))
                else:
                    self.__send_etp_rts(src_address, dest_address, priority, pgn.value, message_size)

            self.__job_thread_wakeup()

        return True


    def async_job_thread(self, now):
        next_wakeup = now + 5.0 # wakeup in 5 seconds

        # check receive buffers for timeout
        # using "list(x)" to prevent "RuntimeError: dictionary changed size during iteration"
        for bufid in list(self._rcv_buffer):
            buf = self._rcv_buffer[bufid]
            if buf['deadline'] != 0:
                if buf['deadline'] > now:
                    if next_wakeup > buf['deadline']:
                        next_wakeup = buf['deadline']
                else:
                    # deadline reached
                    logger.info("Deadline reached for rcv_buffer src 0x%02X dst 0x%02X", buf['src_address'], buf['dest_address'] )
                    if buf['dest_address'] != ParameterGroupNumber.Address.GLOBAL:
                        # TODO: should we handle retries?
                        if buf['transfer_type'] == self.TransferType.TP:
                            self.__send_tp_abort(buf['dest_address'], buf['src_address'], self.ConnectionAbortReason.TIMEOUT, buf['pgn'])
                        else:
                            self.__send_etp_abort(buf['dest_address'], buf['src_address'], self.ExtendedConnectionAbortReason.TIMEOUT, buf['pgn'])
                    # TODO: should we notify our CAs about the cancelled transfer?
                    del self._rcv_buffer[bufid]

        # check send buffers
        # using "list(x)" to prevent "RuntimeError: dictionary changed size during iteration"
        for bufid in list(self._snd_buffer):
            buf = self._snd_buffer[bufid]
            if buf['deadline'] != 0:
                if buf['deadline'] > now:
                    if next_wakeup > buf['deadline']:
                        next_wakeup = buf['deadline']
                else:
                    # deadline reached
                    if buf['state'] == self.SendBufferState.WAITING_CTS:
                        logger.info("Deadline WAITING_CTS reached for snd_buffer src 0x%02X dst 0x%02X", buf['src_address'], buf['dest_address'] )
                        if buf['transfer_type'] == self.TransferType.TP:
                            self.__send_tp_abort(buf['src_address'], buf['dest_address'], self.ConnectionAbortReason.TIMEOUT, buf['pgn'])
                        else:
                            self.__send_etp_abort(buf['dest_address'], buf['src_address'], self.ExtendedConnectionAbortReason.TIMEOUT, buf['pgn'])
                        # TODO: should we notify our CAs about the cancelled transfer?
                        del self._snd_buffer[bufid]
                    elif buf['state'] == self.SendBufferState.SENDING_IN_CTS:
                        while buf['next_packet_to_send'] < buf['message_packages']:
                            # This was sanity check for TP, but we don't want it for ETP
                            #package = buf['next_packet_to_send'] % 255
                            package = buf['next_packet_to_send']
                            offset = package * 7
                            data = buf['data'][offset:]
                            if len(data)>7:
                                data = data[:7]
                            else:
                                while len(data)<7:
                                    data.append(255)
                            # However this does need to be modulo 255
                            #data.insert(0, package+1)
                            data.insert(0, (package % 255)+1)

                            # modify the snd_buffer state in anticipation
                            # of the message we are about to transmit

                            buf['next_packet_to_send'] += 1

                            should_break = False
                            if package == buf['next_wait_on_cts']:
                                # wait on next cts
                                buf['state'] = self.SendBufferState.WAITING_CTS
                                buf['deadline'] = time.time() + self.Timeout.T3
                                should_break = True
                            elif self._minimum_tp_rts_cts_dt_interval != None:
                                buf['deadline'] = time.time() + self._minimum_tp_rts_cts_dt_interval
                                should_break = True

                            # state is ready for recv - Now send the message
                            if buf['transfer_type'] == self.TransferType.TP:
                                self.__send_tp_dt(buf['src_address'], buf['dest_address'], data)
                            else:
                                self.__send_etp_dt(buf['src_address'], buf['dest_address'], data)
                            if should_break:
                                break

                        # recalc next wakeup
                        if next_wakeup > buf['deadline']:
                            next_wakeup = buf['deadline']

                    elif buf['state'] == self.SendBufferState.SENDING_BM:
                        # send next broadcast message...
                        offset = buf['next_packet_to_send'] * 7
                        data = buf['data'][offset:]
                        if len(data)>7:
                            data = data[:7]
                        else:
                            while len(data)<7:
                                data.append(255)
                        data.insert(0, buf['next_packet_to_send']+1)

                        # modify the snd_buffer state in anticipation
                        # of the message we are about to transmit

                        buf['next_packet_to_send'] += 1

                        if buf['next_packet_to_send'] < buf['message_packages']:
                            buf['deadline'] = time.time() + self._minimum_tp_bam_dt_interval
                            # recalc next wakeup
                            if next_wakeup > buf['deadline']:
                                next_wakeup = buf['deadline']
                        else:
                            # done
                            del self._snd_buffer[bufid]

                        # state is updated and ready for recv - now send data
                        self.__send_tp_dt(buf['src_address'], buf['dest_address'], data)
                    elif buf['state'] == self.SendBufferState.TRANSMISSION_FINISHED:
                        del self._snd_buffer[bufid]
                    else:
                        logger.critical("unknown SendBufferState %d", buf['state'])
                        del self._snd_buffer[bufid]

        return next_wakeup


    def _process_tp_cm(self, mid, dest_address, data, timestamp):
        """Processes a Transport Protocol Connection Management (TP.CM) message

        :param j1939.MessageId mid:
            A MessageId object holding the information extracted from the can_id.
        :param int dest_address:
            The destination address of the message
        :param bytearray data:
            The data contained in the can-message.
        :param float timestamp:
            The timestamp the message was received (mostly) in fractions of Epoch-Seconds.
        """
        control_byte = data[0]
        pgn = data[5] | (data[6] << 8) | (data[7] << 16)

        src_address = mid.source_address

        if control_byte == self.ConnectionMode.RTS:
            message_size = data[1] | (data[2] << 8)
            message_packages = data[3]
            max_packages_this_cts = data[4] # Maximum number of segments that can be sent in response to one CTS.
            buffer_hash = self._buffer_hash(src_address, dest_address)
            if buffer_hash in self._rcv_buffer:
                # according SAE J1939-21 we have to send an ABORT if an active
                # transmission is already established
                self.__send_tp_abort(dest_address, src_address, self.ConnectionAbortReason.BUSY, pgn)
                return

            # limit max number segments
            max_packages_this_cts = min(max_packages_this_cts, message_packages)

            # open new buffer for this connection
            self._rcv_buffer[buffer_hash] = {
                    'pgn': pgn,
                    'message_size': message_size,
                    'message_packages': message_packages,
                    'next_packet_to_send_cts': min(self._max_cmdt_packets, max_packages_this_cts),
                    'max_cmdt_packages': self._max_cmdt_packets,
                    'num_packages_max_rec': min(self._max_cmdt_packets, max_packages_this_cts),
                    #'data': [],
                    'data': bytearray(),
                    'deadline': time.time() + self.Timeout.T2,
                    'src_address' : src_address,
                    'dest_address' : dest_address,
                    'transfer_type' : self.TransferType.TP
                }

            self.__send_tp_cts(dest_address, src_address, self._rcv_buffer[buffer_hash]['num_packages_max_rec'], 1, pgn)
            self.__job_thread_wakeup()
        elif control_byte == self.ConnectionMode.CTS:
            num_packages = data[1]
            next_package_number = data[2] - 1
            buffer_hash = self._buffer_hash(dest_address, src_address)
            if buffer_hash not in self._snd_buffer:
                self.__send_tp_abort(dest_address, src_address, self.ConnectionAbortReason.RESOURCES, pgn)
                return
            if num_packages == 0:
                # SAE J1939/21
                # receiver requests a pause
                self._snd_buffer[buffer_hash]['deadline'] = time.time() + self.Timeout.Th
                self.__job_thread_wakeup()
                return

            num_packages_all = self._snd_buffer[buffer_hash]["message_packages"]
            if num_packages > num_packages_all:
                logger.debug("CTS: Allowed more packets %d than complete transmission %d", num_packages, num_packages_all)
                num_packages = num_packages_all
            if next_package_number + num_packages > num_packages_all:
                logger.debug("CTS: Allowed more packets %d than needed to complete transmission %d", num_packages, num_packages_all - next_package_number)
                num_packages = num_packages_all - next_package_number

            self._snd_buffer[buffer_hash]['next_wait_on_cts'] = self._snd_buffer[buffer_hash]['next_packet_to_send'] + num_packages - 1

            self._snd_buffer[buffer_hash]['state'] = self.SendBufferState.SENDING_IN_CTS
            self._snd_buffer[buffer_hash]['deadline'] = time.time()
            self.__job_thread_wakeup()
        elif control_byte == self.ConnectionMode.EOM_ACK:
            buffer_hash = self._buffer_hash(dest_address, src_address)
            if buffer_hash not in self._snd_buffer:
                self.__send_tp_abort(dest_address, src_address, self.ConnectionAbortReason.RESOURCES, pgn)
                return
            # TODO: should we inform the application about the successful transmission?
            # Notify subscribers here to be used for the memory access server to know when to send operation complete
            self.__notify_subscribers(mid.priority,pgn,mid.source_address,dest_address,timestamp,data)

            self._snd_buffer[buffer_hash]['state'] = self.SendBufferState.TRANSMISSION_FINISHED
            self._snd_buffer[buffer_hash]['deadline'] = time.time()
            self.__job_thread_wakeup()
        elif control_byte == self.ConnectionMode.BAM:
            message_size = data[1] | (data[2] << 8)
            message_packages = data[3]
            buffer_hash = self._buffer_hash(src_address, dest_address)
            if buffer_hash in self._rcv_buffer:
                # TODO: should we deliver the partly received message to our CAs?
                del self._rcv_buffer[buffer_hash]
                self.__job_thread_wakeup()

            # init new buffer for this connection
            self._rcv_buffer[buffer_hash] = {
                    "pgn": pgn,
                    "message_size": message_size,
                    "message_packages": message_packages,
                    "next_packet": 1,
                    "max_cmdt_packages": self._max_cmdt_packets,
                    "data": bytearray(),
                    "deadline": time.time() + self.Timeout.T1,
                    'src_address' : src_address,
                    'dest_address' : dest_address,
                    'transfer_type' : self.TransferType.TP
                }
            self.__job_thread_wakeup()
        elif control_byte == self.ConnectionMode.ABORT:
            # if abort received before transmission established -> cancel transmission
            buffer_hash = self._buffer_hash(dest_address, src_address)
            if buffer_hash in self._snd_buffer and self._snd_buffer[buffer_hash]['state'] == self.SendBufferState.WAITING_CTS:
                self._snd_buffer[buffer_hash]['state'] = self.SendBufferState.TRANSMISSION_FINISHED
                self._snd_buffer[buffer_hash]['deadline'] = time.time()
            # TODO: any more abort responses?
            pass
        else:
            raise RuntimeError(f"Received TP.CM with unknown control_byte {control_byte}")

    def _process_etp_cm(self, mid, dest_address, data, timestamp):
        control_byte = data[0]
        pgn = data[5] | (data[6] << 8) | (data[7] << 16)
        src_address = mid.source_address
        buffer_hash = self._buffer_hash(src_address, dest_address)

        if control_byte == self.ConnectionMode.ETP_RTS:
            message_size = data[1] + (data[2] << 8) + (data[3] << 16) + (data[4] << 24)
            message_packages = int(message_size / 7) if (message_size % 7 == 0) else int(message_size / 7) + 1 

            if buffer_hash in self._rcv_buffer:
                # according SAE J1939-21 we have to send an ABORT if an active
                # transmission is already established
                logger.critical(f"buffer in hash, had to abort")
                self.__send_etp_abort(dest_address, src_address, self.ExtendedConnectionAbortReason.BUSY, pgn)
                return

            # open new buffer for this connection and setup to wait for DPO
            self._rcv_buffer[buffer_hash] = {
                'pgn'                 : pgn,
                'message_size'        : message_size,
                'message_packages'    : message_packages,
                'next_packet_to_send' : 0,
                'data'                : bytearray(),
                'deadline'            : time.time() + self.Timeout.T2,
                'src_address'         : src_address,
                'dest_address'        : dest_address,
                'state'               : self.SendBufferState.WAITING_ETP_DPO,
                'transfer_type'       : self.TransferType.ETP,
            }
            # send CTS
            self.__send_etp_cts(dest_address, src_address, number_of_packets_this_cts=255, next_packet_this_cts=1, pgn_value=pgn)
            self.__job_thread_wakeup()
        elif control_byte == self.ConnectionMode.ETP_DPO:
            # Make sure we know about this connection
            if buffer_hash not in self._rcv_buffer:
                # This was an ETP_DPO for a connection that we didn't know about, or we weren't waiting for DPO, so abort it
                logger.critical(f"unknown sender aborting")
                self.__send_etp_abort(dest_address, src_address, self.ExtendedConnectionAbortReason.RESOURCES, pgn)
                return
            buf = self._rcv_buffer[buffer_hash]

            # Check if we are in the correct state
            if (buf['state'] != self.SendBufferState.WAITING_ETP_DPO):
                logger.critical(f"UNEXPECTED_DPO {buf['state']}")
                self.__send_etp_abort(dest_address, src_address, self.ExtendedConnectionAbortReason.UNEXPECTED_DPO, pgn)
                return
            
            # Get the data from the ETP_DPO message
            # The ETP_DPO message format is the following:
            #   Byte: 1 Control byte = 22, Extended Data Packeted Operation
            #   Byte: 2 Number of packets to which to apply the offset (1 to 255)
            #   Bytes: 3 to 5 Data packet offset (0 to n) (Always 1 less than bytes 3 to 5 of the ETP.CM_CTS)
            #   Bytes: 6 to 8 PGN of extended packeted message
            max_packages_this_cts = data[1]
            next_package_number = data[2] + (data[3] << 8) + (data[4] << 16)
            
            # if next_package_number != buf['next_packet_to_send_cts']:
                # TBD If it's not what we are expecting then abort
                # Expecting next_package_number according to the state
                
            # limit max number segments
            num_packages_left = buf['message_packages'] - buf['next_packet_to_send']
            num_packages_this_cts = min(max_packages_this_cts, num_packages_left)
            next_packet_to_send_cts = next_package_number + num_packages_this_cts
            # Setup to receive data packets
            buf['next_packet_to_send']     = next_package_number
            buf['next_packet_to_send_cts'] = next_packet_to_send_cts
            # This seems unused buf['max_cmdt_packages'] = self._max_cmdt_packets,
            buf['num_packages_max_rec']    = num_packages_this_cts   # I don't really know aht this is for
            buf['state']                   = self.SendBufferState.RECEIVING_ETP_DT
            buf['deadline']                = time.time() + self.Timeout.T2
            self.__job_thread_wakeup()
        elif control_byte == self.ConnectionMode.ETP_CTS:
            # Get the connection state for this dest-src pair
            buffer_hash = self._buffer_hash(dest_address, src_address)
            if buffer_hash not in self._snd_buffer:
                # This was an ETP_CTS for a connection that we didn't know about, so abort it
                self.__send_etp_abort(dest_address, src_address, self.ConnectionAbortReason.RESOURCES, pgn)
                return
            buf = self._snd_buffer[buffer_hash]

            # Get the data from the ETP_CTS message
            # The ETP_CTS message format is the following:
            #   Byte: 1 Control byte = 21, Extended Clear to Send
            #   Byte: 2 Number of packets to send (0 or 1 to 255)
            #   Bytes: 3 to 5 Next packet number to send (1 to 16 777 215)
            #   Bytes: 6 to 8 PGN of extended packeted message
            num_packages_in_cts = data[1]
            next_package_index = data[2] + (data[3] << 8) + (data[4] << 16) - 1
            # If the number of packets is 0, the receiver requests a pause
            if num_packages_in_cts == 0:
                # SAE J1939/21
                # receiver requests a pause
                buf['deadline'] = time.time() + self.Timeout.Th
                self.__job_thread_wakeup()
                return

            num_packages_all = buf["message_packages"]
 
            num_packages_until_wait_cts = num_packages_in_cts
            if num_packages_in_cts > num_packages_all:
                num_packages_until_wait_cts = num_packages_all
            if next_package_index + num_packages_in_cts > num_packages_all:
                num_packages_until_wait_cts = num_packages_all - next_package_index

            # Respond with ETP_DPO 
            self.__send_etp_dpo(dest_address, src_address, 7, pgn, num_packages_in_cts, next_package_index )

            # Setup to send those data packets and then wait for CTS again
            buf['next_wait_on_cts'] = buf['next_packet_to_send'] + num_packages_until_wait_cts - 1
            buf['state'] = self.SendBufferState.SENDING_IN_CTS
            buf['deadline'] = time.time()

            self.__job_thread_wakeup()
        elif control_byte == self.ConnectionMode.ETP_EOMA:
            # JBECK: I copied this case from the TP version
            buffer_hash = self._buffer_hash(dest_address, src_address)
            if buffer_hash not in self._snd_buffer:
                self.__send_tp_abort(dest_address, src_address, self.ConnectionAbortReason.RESOURCES, pgn)
                return
            # TODO: should we inform the application about the successful transmission?
            # Notify subscribers here to be used for the memory access server to know when to send operation complete
            self.__notify_subscribers(mid.priority,pgn,mid.source_address,dest_address,timestamp,data)

            self._snd_buffer[buffer_hash]['state'] = self.SendBufferState.TRANSMISSION_FINISHED
            self._snd_buffer[buffer_hash]['deadline'] = time.time()
            self.__job_thread_wakeup()
        elif control_byte == self.ConnectionMode.ETP_ABORT:
            # if abort received before transmission established -> cancel transmission
            buffer_hash = self._buffer_hash(dest_address, src_address)
            if buffer_hash in self._snd_buffer and self._snd_buffer[buffer_hash]['state'] == self.SendBufferState.WAITING_CTS:
                self._snd_buffer[buffer_hash]['state'] = self.SendBufferState.TRANSMISSION_FINISHED
                self._snd_buffer[buffer_hash]['deadline'] = time.time()
        else:
            raise RuntimeError(f"Received ETP.CM with unknown control_byte {control_byte}")

    # Note: This handles both TP and ETP 
    def _process_tp_dt(self, mid, dest_address, data, timestamp):
        sequence_number = data[0]

        logger.debug(f"process_tp_dt {sequence_number}")
        
        src_address = mid.source_address
        buffer_hash = self._buffer_hash(src_address, dest_address)
        if buffer_hash not in self._rcv_buffer:
            # TODO: LOG/TRACE/EXCEPTION?
            # We can come up mid-TP (and so not know about this transfer yet - no RTS seen, and
            # this will be annoying to see, so just ditch it.  We silently don't respond to any
            # DT messages that we didn't get an RTS for.
            #logger.critical(f"process_tp_dt {buffer_hash} not in rcv_buffer {self._rcv_buffer}")   
            return
        buf = self._rcv_buffer[buffer_hash]

        # If this is an ETP message, make sure we are in the right state 
        if buf['transfer_type'] == self.TransferType.ETP and buf['state'] != self.SendBufferState.RECEIVING_ETP_DT:
            logger.debug(f"UNEXPECTED_DT {buf['state']}")
            self.__send_etp_abort(dest_address, src_address, self.ExtendedConnectionAbortReason.UNEXPECTED_DT, buf['pgn'])
            return

        # get data
        buf['data'].extend(data[1:])

        # message is complete with sending an acknowledge
        if len(buf['data']) >= buf['message_size']:
            logger.info("finished RCV of PGN {} with size {}".format(buf['pgn'], buf['message_size']))
            # shorten data to message_size
            buf['data'] = buf['data'][:buf['message_size']]
            # finished reassembly
            if dest_address != ParameterGroupNumber.Address.GLOBAL:
                if buf['transfer_type'] == self.TransferType.TP:
                    self.__send_tp_eom_ack(dest_address, src_address, buf['message_size'], buf['message_packages'], buf['pgn'])
                else:
                    self.__send_etp_eom_ack(dest_address, src_address, buf['message_size'], buf['pgn'])
            self.__notify_subscribers(mid.priority, buf['pgn'], src_address, dest_address, timestamp, buf['data'])
            #del buf
            del self._rcv_buffer[buffer_hash]
            self.__job_thread_wakeup()
            return

        # clear to send
        if (dest_address != ParameterGroupNumber.Address.GLOBAL) and (sequence_number >= buf['next_packet_to_send_cts']):

            # send cts
            number_of_packets_that_can_be_sent = min(buf['num_packages_max_rec'], buf['message_packages'] - buf['next_packet_to_send_cts'])
            next_packet_to_be_sent = buf['next_packet_to_send_cts'] + 1
            if buf['transfer_type'] == self.TransferType.TP:
                self.__send_tp_cts(dest_address, src_address, number_of_packets_that_can_be_sent, next_packet_to_be_sent, buf['pgn'])
            else:
                self.__send_etp_cts(dest_address, src_address, number_of_packets_that_can_be_sent, next_packet_to_be_sent, buf['pgn'])
                buf['state'] = self.SendBufferState.WAITING_ETP_DPO

            # calculate next packet number at which a CTS is to be sent
            buf['next_packet_to_send_cts'] = min(buf['next_packet_to_send_cts'] + buf['num_packages_max_rec'], buf['message_packages'])

            buf['deadline'] = time.time() + self.Timeout.T2
            self.__job_thread_wakeup()
            return

        buf['deadline'] = time.time() + self.Timeout.T1
        self.__job_thread_wakeup()

    def __send_tp_dt(self, src_address, dest_address, data):
        pgn = ParameterGroupNumber(0, 235, dest_address)
        mid = MessageId(priority=7, parameter_group_number=pgn.value, source_address=src_address)
        self.__send_message(mid.can_id, True, data)

    def __send_tp_abort(self, src_address, dest_address, reason, pgn_value):
        pgn = ParameterGroupNumber(0, 236, dest_address)
        mid = MessageId(priority=7, parameter_group_number=pgn.value, source_address=src_address)
        data = [self.ConnectionMode.ABORT, reason, 0xFF, 0xFF, 0xFF, pgn_value & 0xFF, (pgn_value >> 8) & 0xFF, (pgn_value >> 16) & 0xFF]
        self.__send_message(mid.can_id, True, data)

    def __send_tp_cts(self, src_address, dest_address, num_packets, next_packet, pgn_value):
        pgn = ParameterGroupNumber(0, 236, dest_address)
        mid = MessageId(priority=7, parameter_group_number=pgn.value, source_address=src_address)
        data = [self.ConnectionMode.CTS, num_packets, next_packet, 0xFF, 0xFF, pgn_value & 0xFF, (pgn_value >> 8) & 0xFF, (pgn_value >> 16) & 0xFF]
        self.__send_message(mid.can_id, True, data)

    def __send_tp_eom_ack(self, src_address, dest_address, message_size, num_packets, pgn_value):
        pgn = ParameterGroupNumber(0, 236, dest_address)
        mid = MessageId(priority=7, parameter_group_number=pgn.value, source_address=src_address)
        data = [self.ConnectionMode.EOM_ACK, message_size & 0xFF, (message_size >> 8) & 0xFF, num_packets, 0xFF, pgn_value & 0xFF, (pgn_value >> 8) & 0xFF, (pgn_value >> 16) & 0xFF]
        self.__send_message(mid.can_id, True, data)

    def __send_tp_rts(self, src_address, dest_address, priority, pgn_value, message_size, num_packets, max_cmdt_packets):
        pgn = ParameterGroupNumber(0, 236, dest_address)
        mid = MessageId(priority=priority, parameter_group_number=pgn.value, source_address=src_address)
        data = [self.ConnectionMode.RTS, message_size & 0xFF, (message_size >> 8) & 0xFF, num_packets, max_cmdt_packets, pgn_value & 0xFF, (pgn_value >> 8) & 0xFF, (pgn_value >> 16) & 0xFF]
        self.__send_message(mid.can_id, True, data)

    def split_to_bytes(self, value, num_bytes):
        return [(value >> (8 * i)) & 0xFF for i in range(num_bytes)]

    def __send_etp_rts(self, src_address, dest_address, priority, pgn_value, message_size):
        # ETP.RTS message definition is as follows:
        #    Byte: 1 Control byte = 20, Extended Request to Send
        #    Bytes: 2 to 5 Number of bytes to transfer (1 786 byte to 117 440 505 byte max.)
        #    Bytes: 6 to 8 PGN of extended packeted message
        pgn = ParameterGroupNumber(0, ParameterGroupNumber.PF.ETP_CM, dest_address)
        mid = MessageId(priority=priority, parameter_group_number=pgn.value, source_address=src_address)
        data = ([self.ConnectionMode.ETP_RTS] +
                 self.split_to_bytes(message_size, 4) +
                 self.split_to_bytes(pgn_value, 3))
        self.__send_message(mid.can_id, True, data)

    def __send_etp_dpo(self, src_address, dest_address, priority, pgn_value, number_of_packets, data_packet_offset):
        # ETP.DPO message definition is as follows:
        #   Byte: 1 Control byte = 22, Extended Data Packet Offset
        #   Byte: 2 Number of packets to which to apply the offset (1 to 255)
        #   Bytes: 3 to 5 Data packet offset (0 to n) (Always 1 less than bytes 3 to 5 of the ETP.CM_CTS)
        #   Bytes: 6 to 8 PGN of extended packeted message
        pgn = ParameterGroupNumber(0, ParameterGroupNumber.PF.ETP_CM, dest_address)
        mid = MessageId(priority=priority, parameter_group_number=pgn.value, source_address=src_address)

        data = ([self.ConnectionMode.ETP_DPO] +
                 self.split_to_bytes(number_of_packets, 1) +
                 self.split_to_bytes(data_packet_offset, 3) +
                 self.split_to_bytes(pgn_value, 3))
        self.__send_message(mid.can_id, True, data)

    def __send_etp_dt(self, src_address, dest_address, data):
        pgn = ParameterGroupNumber(0, ParameterGroupNumber.PF.ETP_DT, dest_address)
        mid = MessageId(priority=7, parameter_group_number=pgn.value, source_address=src_address)
        self.__send_message(mid.can_id, True, data)

    def __send_etp_cts(self, src_address, dest_address, number_of_packets_this_cts, next_packet_this_cts, pgn_value):
        # ETP.CTS message definition is as follows:
        # Byte: 1 Control byte = 21, Extended Clear to Send
        # Byte: 2 Number of packets to send (0 or 1 to 255)
        # Bytes: 3 to 5 Next packet number to send (1 to 16 777 215)
        # Bytes: 6 to 8 PGN of extended packeted message
        pgn = ParameterGroupNumber(0, ParameterGroupNumber.PF.ETP_CM, dest_address)
        mid = MessageId(priority=7, parameter_group_number=pgn.value, source_address=src_address)
        data = ([self.ConnectionMode.ETP_CTS] +
                 self.split_to_bytes(number_of_packets_this_cts, 1) +
                 self.split_to_bytes(next_packet_this_cts, 3) +
                 self.split_to_bytes(pgn_value, 3))
        self.__send_message(mid.can_id, True, data)
    
    def __send_etp_eom_ack(self, src_address, dest_address, message_size, pgn_value):
        # ETP.EOMA message definition is as follows:
        #   Byte: 1 Control byte = 23, Extended End-of-Message Acknowledgement
        #   Bytes: 2 to 5 Number of bytes transferred (1 786 byte to 117 440 505 byte)
        #   Bytes: 6 to 8 PGN of extended packeted message
        pgn = ParameterGroupNumber(0, ParameterGroupNumber.PF.ETP_CM, dest_address)
        mid = MessageId(priority=7, parameter_group_number=pgn.value, source_address=src_address)
        data = ([self.ConnectionMode.ETP_EOMA] +
                 self.split_to_bytes(message_size, 4) +
                 self.split_to_bytes(pgn_value, 3))
        self.__send_message(mid.can_id, True, data)

    def __send_etp_abort(self, src_address, dest_address, reason: ExtendedConnectionAbortReason, pgn_value):
        # ETP.ABORT message definition is as follows:
        #   Byte: 1 Control byte = 255, Connection AbortByte: 2 Connection Abort reason
        #   Bytes: 3 to 5 Reserved for assignment by ISO, these bytes should be set to FF16
        #   Bytes: 6 to 8 PGN of packeted message
        pgn = ParameterGroupNumber(0, ParameterGroupNumber.PF.ETP_CM, dest_address)
        mid = MessageId(priority=7, parameter_group_number=pgn.value, source_address=src_address)
        data = ([self.ConnectionMode.ETP_ABORT] +
                self.split_to_bytes(reason, 1) +
                [0xFF] * 3 +
                self.split_to_bytes(pgn_value, 3))
        self.__send_message(mid.can_id, True, data)

    def __send_acknowledgement(self, control_byte, group_function_value, address_acknowledged, pgn):
        data = [control_byte, group_function_value, 0xFF, 0xFF, address_acknowledged, (pgn & 0xFF), ((pgn >> 8) & 0xFF), ((pgn >> 16) & 0xFF)]
        mid = MessageId(priority=6, parameter_group_number=0x00E800, source_address=255)
        self.__send_message(mid.can_id, True, data)

    def __send_tp_bam(self, src_address, priority, pgn_value, message_size, num_packets):
        pgn = ParameterGroupNumber(0, 236, ParameterGroupNumber.Address.GLOBAL)
        mid = MessageId(priority=priority, parameter_group_number=pgn.value, source_address=src_address)
        data = [self.ConnectionMode.BAM, message_size & 0xFF, (message_size >> 8) & 0xFF, num_packets, 0xFF, pgn_value & 0xFF, (pgn_value >> 8) & 0xFF, (pgn_value >> 16) & 0xFF]
        self.__send_message(mid.can_id, True, data)

    def notify(self, can_id, data, timestamp):
        """Feed incoming CAN message into this ecu.

        If a custom interface is used, this function must be called for each
        29-bit standard message read from the CAN bus.

        :param int can_id:
            CAN-ID of the message (always 29-bit)
        :param bytearray data:
            Data part of the message (0 - 8 bytes)
        :param float timestamp:
            The timestamp field in a CAN message is a floating point number
            representing when the message was received since the epoch in
            seconds.
            Where possible this will be timestamped in hardware.
        """
        mid = MessageId(can_id=can_id)
        pgn = ParameterGroupNumber()
        pgn.from_message_id(mid)

        if pgn.is_pdu2_format:
            # direct broadcast
            self.__notify_subscribers(mid.priority, pgn.value, mid.source_address, ParameterGroupNumber.Address.GLOBAL, timestamp, data)
            return

        # peer to peer
        # pdu_specific is destination Address
        pgn_value = pgn.value & 0x1FF00
        dest_address = pgn.pdu_specific # may be Address.GLOBAL

        # iterate all CAs to check if we have to handle this destination address
        if dest_address != ParameterGroupNumber.Address.GLOBAL:
            if not self.__ecu_is_message_acceptable(dest_address): # simple peer-to-peer reception without adding a controller-application
                reject = True
                for ca in self._cas:
                    if ca.message_acceptable(dest_address):
                        reject = False
                        break
                if reject == True:
                    return

        if pgn_value == ParameterGroupNumber.PGN.ADDRESSCLAIM:
            for ca in self._cas:
                ca._process_addressclaim(mid, data, timestamp)
        elif pgn_value == ParameterGroupNumber.PGN.REQUEST:
            for ca in self._cas:
                if ca.message_acceptable(dest_address):
                    ca._process_request(mid, dest_address, data, timestamp)
        elif pgn_value == ParameterGroupNumber.PGN.TP_CM:
            self._process_tp_cm(mid, dest_address, data, timestamp)

        elif pgn_value == ParameterGroupNumber.PGN.DATATRANSFER or pgn_value == ParameterGroupNumber.PGN.ETP_DT:
            self._process_tp_dt(mid, dest_address, data, timestamp)
        elif pgn_value == ParameterGroupNumber.PGN.ETP_CM:
            self._process_etp_cm(mid, dest_address, data, timestamp)
        else:
            self.__notify_subscribers(mid.priority, pgn_value, mid.source_address, dest_address, timestamp, data)
            return


