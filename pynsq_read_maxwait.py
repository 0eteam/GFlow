import pickle
import time
start = time.time()
import nsq
import threading
import tornado


class Get_flow(object):
    def __init__(self, num, maxWaitingTime):
        self.data = []
        self.num = num
        self.temp = 0
        self.maxWatingTime = maxWaitingTime
        self.read_lock = threading.Lock()
        self.ioloop = tornado.ioloop.IOLoop.instance()

    def get_flow_func(self, number):
        def handler(message):
            try:
                if len(self.data) < number:
                    self.read_lock.acquire()
                    message.enable_async()
                    self.data.append(pickle.loads(message.body))
                    # print(str(message.body, encoding='utf-8'))
                    message.finish()
                    self.read_lock.release()
                else:
                    self.ioloop.add_callback(self.ioloop.stop)
                return True
            except Exception as e:
                # print(e)
                pass

        try:
            r = nsq.Reader(
                message_handler=handler,
                nsqd_tcp_addresses=['192.168.3.30:4150'],
                topic='flow',
                channel='read',
                max_in_flight=1)
            self.ioloop.start()
        except Exception as e:
            # print(e)
            pass

    def get_flow(self):
        try:
            self.data = []
            self.startTime = time.time()
            self.endTime = time.time()
            while self.temp != 1:
                if self.endTime - self.startTime > self.maxWatingTime:
                    self.temp = 1
                    break
                elif len(self.data) < self.num:
                    t = threading.Thread(target=self.get_flow_func, args=(self.num, ))
                    t.start()
                    t.join(timeout=self.maxWatingTime)
                    self.endTime = time.time()
                elif len(self.data) >= self.num:
                    self.data = self.data[:self.num]
                    break
            return self.data, self.temp
        except Exception as e:
            # print(e)
            pass

if __name__ == "__main__":
    import binascii
    def decodeLoad(data):
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
        # newLoad += '\n'
        return newLoad

    f = open('20201210.txt', 'a')
    get_fl = Get_flow(10)#一次性从nsq消息队列中读取
    for i in range(1000):
        data = get_fl.get_flow()
        for flow in data:
            # 遇到单引号时，抛出错误
            try:
                print('aaaa', flow)
                flow = pickle.loads(flow)  # 将str类型转换成字典
                print('bbb', flow)
            except Exception as e:
                continue
            # print(flow)
            proto = flow['all_data'][-1]['application_name']
            packet_num = flow['packet_num']  # 该流中含有的数据包总数
            all_data = flow['all_data']
            for j in range(packet_num-1):
                payload = all_data[j]['ip_packet_binary']
                payloadLen = all_data[j]['payload_size']
                payload = decodeLoad(payload).split(" ")[-payloadLen:]
                print(payload)
                f.write(str(payload))
                f.write('\n')
    f.close()


    end = time.time()
    print("totaltime:{0}s".format(end-start))
