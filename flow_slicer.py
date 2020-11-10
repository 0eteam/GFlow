from nfstream import NFStreamer, NFPlugin
import binascii
import nsq
import tornado


im_every_flow = {}  # all flow (_C, id) of myself
im_flow_id = -1
im_flow_data = {}
writer = nsq.Writer(['127.0.0.1:4150'])


class FlowSlicer(NFPlugin):

    def decodeLoad(self, data):
        """
        :param data:二进制data
        :return: 字符串data
        """
        str = binascii.b2a_hex(data).decode()
        if str == '00':
            return None
        newLoad = ''
        i = 0
        for j in range(0, len(str), 2):
            newLoad += str[j:j + 2] + ' '
        newLoad = newLoad[:-1]
        newLoad += '\n'
        return newLoad

    def on_init(self, packet, flow):
        '''
        :param packet:
        :param flow:
        :return:
        '''
        global im_flow_id
        global im_flow_data
        global im_every_flow

        # print(type(flow._C), flow._C)
        im_flow_id += 1
        im_every_flow.setdefault(str(flow._C), im_flow_id)
        tmp_ip_packet = self.decodeLoad(packet.ip_packet[-int(packet.payload_size):])
        tmp_dict = {
            'type': 'packet1',
            'src_ip': packet.src_ip,
            'src_port': packet.src_port,
            'dst_ip': packet.dst_ip,
            'dst_port': packet.dst_port,
            'protocol': packet.protocol,
            'ip_packet': tmp_ip_packet,
            'ip_packet_binary': packet.ip_packet,
            'syn': packet.syn,
            'cwr': packet.cwr,
            'ece': packet.ece,
            'urg': packet.urg,
            'ack': packet.ack,
            'psh': packet.psh,
            'rst': packet.rst,
            'fin': packet.fin,
            'ip_version': packet.ip_version,
            'vlan_id': packet.vlan_id,
            'time': packet.time,
            'delta_time': packet.delta_time,
            'direction': packet.direction,
            'raw_size': packet.raw_size,
            'ip_size': packet.ip_size,
            'transport_size': packet.transport_size,
            'payload_size': packet.payload_size
        }
        tmp_list = []
        tmp_list.append(tmp_dict)
        im_flow_data.setdefault(im_flow_id, tmp_list)
        # print(im_flow_data)


    def on_update(self, packet, flow):
        '''
        :param packet:
        :param flow:
        :return:
        '''
        global im_flow_id
        global im_flow_data
        global im_every_flow
        # b'E\x00\x004\xd5\x17@\x004\x06\xe38\x170\xc9\x08\xac\x13\x02(\x00P\x
        # print(packet.ip_packet)
        # 45 00 00 34 d5 17 40 00 34 06 e3 38 17 30 c9 08 ac 13 02 28 00 50
        # print(self.decodeLoad(packet.ip_packet))
        try:
            tmp_flow_C = str(flow._C)
            tmp_list_id = int(im_every_flow.get(tmp_flow_C))
            tmp_ip_packet = self.decodeLoad(packet.ip_packet[-int(packet.payload_size):])
            tmp_dict = {
                'type': 'packet' + str(len(im_flow_data[tmp_list_id]) + 1),
                'src_ip': packet.src_ip,
                'src_port': packet.src_port,
                'dst_ip': packet.dst_ip,
                'dst_port': packet.dst_port,
                'protocol': packet.protocol,
                'ip_packet': tmp_ip_packet,
                'ip_packet_binary': packet.ip_packet,
                'syn': packet.syn,
                'cwr': packet.cwr,
                'ece': packet.ece,
                'urg': packet.urg,
                'ack': packet.ack,
                'psh': packet.psh,
                'rst': packet.rst,
                'fin': packet.fin,
                'ip_version': packet.ip_version,
                'vlan_id': packet.vlan_id,
                'time': packet.time,
                'delta_time': packet.delta_time,
                'direction': packet.direction,
                'raw_size': packet.raw_size,
                'ip_size': packet.ip_size,
                'transport_size': packet.transport_size,
                'payload_size': packet.payload_size
            }
            im_flow_data[tmp_list_id].append(tmp_dict)
        except Exception as e:
            print("error:", e)

    def on_expire(self, flow):
        '''
        :param flow:
        :return:
        '''
        global im_flow_id
        global im_flow_data
        global im_every_flow
        global writer

        try:
            # print(im_every_flow)
            tmp_flow_C = str(flow._C)
            tmp_list_id = int(im_every_flow.get(str(tmp_flow_C)))
            tmp_flow_dict = {
                'type': 'flow'+str(tmp_list_id)
            }
            for alli in range(0, 85):
                tmp_flow_dict[flow.keys()[alli]] = flow.values()[alli]

            im_flow_data[tmp_list_id].append(tmp_flow_dict)
            tmp_all_data = im_flow_data[tmp_list_id]
            tmp_flow_all = {
                'flow_id': tmp_list_id,
                'packet_num': len(tmp_all_data)-1,
                'all_data': tmp_all_data
            }
            print(tmp_flow_all)
            tmp_flow_all = str(tmp_flow_all)

            im_every_flow.pop(tmp_flow_C)
            im_flow_data.pop(tmp_list_id)
            # print("expire:" + str(len(im_every_flow)))

            print("fin_rest_num:", len(im_every_flow), len(im_flow_data))
            # with open('other.txt', 'a+') as f:
            #     f.write(tmp_flow_all)
            #     f.write('\n')

            # @tornado.gen.coroutine
            # def do_pub():
            #     # yield tornado.gen.sleep(1)
            #     writer.pub("flow", bytes(tmp_flow_all, encoding='utf-8'))
            # tornado.ioloop.IOLoop.instance().run_sync(do_pub)

        except Exception as e:
            print("error:", e)
        # print("expire:", flow)
        pass

# main func
my_streamer = NFStreamer(source="ens33",  # or network interface
                         decode_tunnels=True,
                         bpf_filter=None,
                         promiscuous_mode=True,
                         snapshot_length=1536,
                         idle_timeout=15,
                         active_timeout=120,
                         accounting_mode=0,
                         udps=FlowSlicer(),
                         n_dissections=20,
                         statistical_analysis=True,
                         splt_analysis=28,
                         n_meters=0,
                         performance_report=0)

for flow in my_streamer:
    print("")

