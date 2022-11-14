#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""
@File    :   throughout   
@Contact :   18645369158@163.com

@Modify Time      @Author    @Version    @Description
------------      -------    --------    -----------
2022/9/25         LanceYuan  1.0         None
"""


def throughout_get(time_list, length_list, grain):
    """
    通过粒度计算吞吐量变化趋势
    :param time_list:
    :param length_list:
    :param grain:
    :return:
    """
    last_time = 0
    sum_length = 0
    res_time_list = []
    res_length = []
    for time, length in zip(time_list, length_list):
        if time - last_time >= grain:
            res_time_list.append(grain * len(res_time_list))
            res_length.append(sum_length)
            last_time = time
            sum_length = 0
        else:
            sum_length += length


    return {"time": res_time_list, "length": res_length}



