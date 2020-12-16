from nfstream import NFStreamer, NFPlugin
import binascii
import nsq
import tornado
import redis
import pickle

pool = redis.ConnectionPool(
    host="localhost",
    port=6379,
    db=0,
    max_connections=8000
)

r = redis.Redis(connection_pool=pool)
r.flushdb()

import time
start = time.time()

import logging
logging.basicConfig(level=logging.INFO)

writer = nsq.Writer(['127.0.0.1:4150'])

# x = 0

# f = open('/mnt/hgfs/share/123.txt', 'a+')
class FlowSlicer(NFPlugin):
    def on_init(self, packet, flow):
        '''
        :param packet:
        :param flow:
        :return:
        '''
        try:
            # global x
            tmp_dict = {
                'type': 'packet',
                'src_ip': packet.src_ip,
                'src_port': packet.src_port,
                'dst_ip': packet.dst_ip,
                'dst_port': packet.dst_port,
                'protocol': packet.protocol,
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
            r.rpush(str(flow._C)[-9:-1], str(tmp_dict))
            # print(tmp_dict)
            # r.expire(str(flow._C)[-9,-1], 300)
            # x += 1
            # print("init:{0}".format(x))
            # print("init")
        except Exception as e:
            print(e)


    def on_update(self, packet, flow):
        '''
        :param packet:
        :param flow:
        :return:
        '''
        try:
            tmp_dict = {
                'type': 'packet',
                'src_ip': packet.src_ip,
                'src_port': packet.src_port,
                'dst_ip': packet.dst_ip,
                'dst_port': packet.dst_port,
                'protocol': packet.protocol,
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
            r.rpush(str(flow._C)[-9:-1], str(tmp_dict))
        except Exception as e:
            print("error:", e)

    def on_expire(self, flow):
        '''
        :param flow:
        :return:
        '''

        try:
            tmp_flow_dict = {
                'type': 'flow'
            }
            for alli in range(0, 85):
                tmp_flow_dict[flow.keys()[alli]] = flow.values()[alli]

            # redis
            tmp_all_data = []
            result = r.lrange(str(flow._C)[-9:-1], 0, -1)
            for one in result:
                one = eval(str(one, encoding='utf-8'))
                # print(one)
                # print(type(one))
                tmp_all_data.append(one)
            # print(tmp_flow_dict)
            # print(type(tmp_flow_dict))
            tmp_all_data.append(tmp_flow_dict)
            # print(type(tmp_all_data))

            tmp_flow_all = {
                'packet_num': len(tmp_all_data)-1,
                'all_data': tmp_all_data
            }
            r.delete(str(flow._C)[-9:-1])

            # print(tmp_flow_all)
            # print(type(tmp_flow_all))
            # print(pickle.dumps(tmp_flow_all))
            # print(pickle.loads(pickle.dumps(tmp_flow_all)))

            # f.write(tmp_flow_all)
            # f.write('\n')
            # print("expire")

            @tornado.gen.coroutine
            def do_pub():
                # yield tornado.gen.sleep(1)
                writer.pub("flow", pickle.dumps(tmp_flow_all))
            tornado.ioloop.PeriodicCallback(do_pub, 100).start()
            # nsq.run()  # error
            # tornado.ioloop.IOLoop.instance().run_sync(do_pub)

        except Exception as e:
            print("error:", e)

# main func
my_streamer = NFStreamer(source="/mnt/hgfs/share/ISCX_Botnet-Training.pcap",  # or network interface
                         decode_tunnels=True,
                         bpf_filter=None,
                         promiscuous_mode=True,
                         snapshot_length=1536,
                         idle_timeout=120,
                         active_timeout=120,
                         accounting_mode=0,
                         udps=FlowSlicer(),
                         n_dissections=20,
                         statistical_analysis=True,
                         splt_analysis=28,
                         n_meters=0,
                         performance_report=0)

i = 0
for flow in my_streamer:
    i += 1
    print(i)

del r
# f.close()

end = time.time()
print("total time: {end_time} s".format(end_time=(end-start)))