#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""
@File    :   main   
@Contact :   18645369158@163.com

@Modify Time      @Author    @Version    @Description
------------      -------    --------    -----------
2022/9/13        LanceYuan  1.0         None
"""
from pcap_analyze.Reader import Transport_data
from visualization.draw import scatter, line
from tools import throughout
import os


if __name__ == '__main__':
    base_path = "./source_pcap/tcp_congestion_control/"
    for file_path in os.listdir(base_path):
        data_reader = Transport_data(f"{base_path}{file_path}")
        traffic_data = data_reader.get_tcp_time_data()
        scatter(traffic_data["time_all"], traffic_data["pack_all"], file_path+"_traffic_data", f"./res/{file_path.split('.')[0]}_traffic_data.jpg")
        res = throughout.throughout_get(traffic_data["time_all"], traffic_data["pack_all"], 0.01)
        cwnd = data_reader.get_time_window()
        line(range(len(cwnd[0])), cwnd[0], file_path+"_cwnd", f"./res/{file_path.split('.')[0]}_cwnd.jpg")
        line(range(len(cwnd[1])), cwnd[1], file_path + "_cwnd", f"./res/{file_path.split('.')[0]}_cwnd_2.jpg")
        line(res["time"], res["length"], file_path+"_throughout", f"./res/{file_path.split('.')[0]}_throughout.jpg")
        print("finish " + file_path)


