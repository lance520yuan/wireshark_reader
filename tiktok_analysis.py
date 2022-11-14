#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""
@File    :   tiktok_analysis   
@Contact :   18645369158@163.com

@Modify Time      @Author    @Version    @Description
------------      -------    --------    -----------
2022/10/26        LanceYuan  1.0         None
"""
from pcap_analyze.Reader import Transport_data
from visualization.draw import scatter, line
from tools import throughout
import os


if __name__ == '__main__':
    path = "./source_pcap/app/快手.pcap"
    data_reader = Transport_data(path)
    file_path = "test"
    inflight_list = data_reader.get_res()
    for name, inflight in inflight_list.items():
        line(inflight[0], inflight[1], f"from IP {name}", f"./res3/{name}_inflight.jpg")
    print("finish " + file_path)


