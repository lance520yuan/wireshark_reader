#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""
@File    :   scatter   
@Contact :   18645369158@163.com

@Modify Time      @Author    @Version    @Description
------------      -------    --------    -----------
2022/9/27        LanceYuan  1.0         None
"""
import matplotlib.pyplot as plt
import matplotlib

matplotlib.use('TkAgg')


def scatter(x, y, title="test", path="test.jpg"):
    plt.figure(figsize=(20, 5))
    plt.scatter(x, y)
    plt.title(title)
    plt.savefig(path)


def line(x, y, title="test", path="test.jpg"):
    plt.figure(figsize=(20, 5))
    plt.plot(x, y)
    plt.title(title)
    plt.savefig(path)
