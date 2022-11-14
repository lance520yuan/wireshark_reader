#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""
@File    :   Reader   
@Contact :   18645369158@163.com

@Modify Time      @Author    @Version    @Description
------------      -------    --------    -----------
2022/9/13         LanceYuan  1.0         暂时只能针对一条流进行获取窗口和吞吐量
"""
import os

from scapy.all import *
from scapy.layers.dns import *
from scapy.layers.l2 import *
from scapy.layers.inet import *
from scapy.layers.inet6 import *

import numpy as np

import json

# 超参数设置及解析
# 对应关系
# F: Fin
# S: SYN
# R: Reset
# P: Push
# A: Ack
# U: Urgent
# E: ECN-Echo
# C: Congestion Window Reduced (CWR)
# N: Nonce
tcp_flag = 'FSRPAUECN'


class TCP_data:
    def __init__(self, pcap_data: Ether):
        # pcap 信息
        # time 可以转化为相对时间，这边现实的时间是自 1970-01-01后经过的秒数
        self.length_with_head = pcap_data.wirelen
        self.time = pcap_data.time

        # todo: 暂时默认 IPV4
        ip_data = pcap_data.getlayer(IP)
        self.tag = ""
        self.src_ip = ip_data.src
        self.dst_ip = ip_data.dst
        # 设置数据链表信息
        self.next_tcp = None
        self.previous_tcp = None
        # 读取 tcp 数据
        self.tcp_data = pcap_data.getlayer(TCP)
        self.len_without_head = None
        self.source_port = self.tcp_data.sport
        self.destination_port = self.tcp_data.dport
        # 如果初始ack为0 则可能是第一条数据
        self.seq = self.tcp_data.seq
        self.ack = self.tcp_data.ack
        self.windows_size = self.tcp_data.window
        self.chksum = self.tcp_data.chksum
        # 设置 TCP 标志位
        self.flags_name = str(self.tcp_data.flags)
        # 设置空飘数值
        self.inflight = 0

    def __str__(self):
        print("src_ip:", self.src_ip, "dst_ip", self.dst_ip)

    def set_inflight(self, set_value):
        self.inflight = set_value


class UDP_data:
    pass


class Transport_data:
    """
    数据读取类
    """
    def __init__(self, data_path):
        """
        给定数据文件路径，初始化数据读取器
        :param data_path: 读取位置路径
        """
        # 读取原始 pcap 数据
        self.source_traffic_data = rdpcap(data_path)
        # 初始化加入序列
        # 设置最开始的 src_ack src_seq dst_ack dst_seq
        # 暂时认为 src 是 host 主机
        self.src_ack = 0
        self.src_seq = 0
        self.dst_ack = 0
        self.dst_seq = 0
        # 统计最大访问作为主机IP
        ip_list = list()

        for index, pcap in enumerate(self.source_traffic_data):
            if index == 0:
                self.base_time = pcap.time
            if pcap.haslayer(IP):
                ip_list.append(pcap.getlayer(IP).src)
                ip_list.append(pcap.getlayer(IP).dst)

        self.ip_list = collections.Counter(ip_list)

        self.host_ip = list(self.ip_list.keys())[1]
        self.dst_ip_list = list(dict(self.ip_list).keys())
        self.dst_ip_list.remove(self.host_ip)
        # self.dst_ip_list.remove('192.168.137.1')
        # 定义每条传输使用数据
        self.tcp_data = {}
        for _tcp_ip in self.dst_ip_list:
            self.tcp_data[_tcp_ip] = []
        self.udp_data = []
        self.tcp_statistics()

    def tcp_statistics(self):
        """
        统计全部数据中包含的可能 TCP 或 UDP 包信息
        TODO：目前只统计 TCP，UDP 及 QUIC 放在之后统计
        :return:
        """
        for index, pcap in enumerate(self.source_traffic_data):
            if pcap.haslayer(TCP):
                temp_tcp = TCP_data(pcap)
                # 这个位置要根据交互 TCP 的不同做定性区分
                if temp_tcp.src_ip == self.host_ip:
                    self.tcp_data[temp_tcp.dst_ip].append(temp_tcp)
                else:
                    self.tcp_data[temp_tcp.src_ip].append(temp_tcp)
            elif pcap.haslayer(UDP):
                udp = pcap.getlayer(UDP)

    def get_res(self):
        res = {}
        for _key, _value in self.tcp_data.items():
            if len(_value) > 100:
                _t, _r = self.get_time_window(_value)
                res[_key] = (_t, _r)
        return res

    def get_tcp_time_data(self):
        time_stamp = []
        time_in = []
        time_out = []
        pack_len = []
        pack_in = []
        pack_out = []
        for _tcp in self.tcp_data:
            time_stamp.append(_tcp.time - self.base_time)
            pack_len.append(_tcp.length_with_head)
            if self.host_ip == _tcp.src_ip:
                time_in.append(_tcp.time - self.base_time)
                pack_in.append(_tcp.length_with_head)
            else:
                time_out.append(_tcp.time - self.base_time)
                pack_out.append(_tcp.length_with_head)
        return {
            "time_all": time_stamp,
            "pack_all": pack_len,
            "time_in": time_in,
            "pack_in": pack_in,
            "time_out": time_out,
            "pack_out": pack_out
        }

    def get_time_window(self, tcp_list):
        _time_list = []
        src_cwnd_list = []
        dst_cwnd_list = []
        src_ack = self.src_ack
        dst_ack = self.dst_ack
        for _tcp in tcp_list:
            if "A" in _tcp.flags_name:
                if _tcp.src_ip == self.host_ip:
                    src_ack = _tcp.ack
                else:
                    dst_ack = _tcp.ack
            if "P" in _tcp.flags_name:
                if _tcp.src_ip == self.host_ip:
                    src_cwnd_list.append(_tcp.seq - dst_ack)
                    _tcp.set_inflight(src_cwnd_list[-1])
                else:
                    dst_cwnd_list.append(_tcp.seq - src_ack)
                    _time_list.append(_tcp.time)
                    _tcp.set_inflight(dst_cwnd_list[-1])
        # 前两个数据有可能为 SYN 数据 这个时刻前的ACK并不存在，因此需要将前两个时刻的ACK注释掉
        # src_cwnd_list.pop(0)
        # dst_cwnd_list.pop(0)
        return _time_list, dst_cwnd_list




