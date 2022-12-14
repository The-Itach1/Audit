# IDAPython Audit

## 引言 ##
最近复现学习了下Tenda固件相关的一些cve，只不过网上关于固件分析的文章确实很少，或者是不够详细。为了方便代码审计，发现了一个可以在mips架构下获取到危险函数信息的一个idapython 插件mipsAudit，链接在参考中。

然后我发现，其对于printf，sprintf，里面的字符串的获取实际上并不是太理想，并且不支持arm架构，然后就想着也学习下idapython脚本的编写，去在其基础上继续完善，删除了一些没必要的代码，和写了一个支持arm的审计脚本，并将其合并。

但是在后面的使用过程中发现，对于具体参数(特别是具体的字符串)的获取通用性实在是太差了，在我分析的程序中，字符串的查询可以达到95%，在其他程序使用可能就是0%。感觉每个程序都可能需要再次进行修改，因为不知道获得具体的字符串需要寻找几次。

所以可以作为学习编写idapython脚本的一个练习，真正有实际需求的时候在自己根据程序指令特色进行修改。
## 简介 ##
github地址：

支持arm架构和mips架构的危险函数审计脚本，文件有3个。

- ArmAudit.py	支持arm的审计脚本
- MipsAudit.py	支持mips的审计脚本
- A_M_Audit.py	我为了方便将其整合到了一个脚本里面。

然后example文件夹装的是我在开发时使用的两个样本程序，一个arm，一个mips，分别来自于Tenda AX1806的US_AX1806V2.0br_v1.0.0.1_cn_2990_ZGDX01_2.bin和Tenda AC9的US_AC9V3.0RTL_V15.03.06.42_multi_TD01.bin

支持ida7.5，ida7.6。

大家可以根据需要自己选择，然后根据自己需求，然后对其修改，供自己分析时使用。


## 缺点 ##
只支持32位程序，因为64位可能某些指令处理的不同，会导致脚本失效，我也没有测试过。

可能会因为不同程序的指令流程导致脚本获取某些参数失效，而且大部分程序的指令流程都不同，这意味着如果想获取准确的参数，比如说字符串，可能一些程序只用寻找一次，一些是2两次，并且在同一个程序中寻找的次数也不同。

## 功能 ##
对于常见的危险函数进行记录，记录的内容包括函数名称，函数调用地址并高亮显示，以及调用的参数，并且将相关参数的注释写到汇编代码中，如果不想覆盖原注释，可以到源码中去修改设置注释函数的flag为1。

arm架构下。
![](https://github.com/The-Itach1/Audit/blob/master/image/Snipaste_2022-08-03_22-24-55.png)

mips架构如下。
![](https://github.com/The-Itach1/Audit/blob/master/image/Snipaste_2022-08-03_22-41-50.png)

## 使用 ##
- 依赖 `prettytable`，`pip3 install prettytable --target="D:\xxxx\IDA 7.5\python\3"`
- 将py文件复制到plugins目录下。
- ida加载程序后Edit->Plugins->A_M_Audit

## 参考 ##
[https://github.com/t3ls/mipsAudit](https://github.com/t3ls/mipsAudit)

[https://github.com/giantbranch/mipsAudit](https://github.com/giantbranch/mipsAudit)
