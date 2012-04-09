WinPcap4.10 bate的手动安装方法

          www.chinahacker.net



1，安装需要用到以下文件，Packet.dll，WanPacket.dll，wpcap.dll，pthreadVC.dll,npf.sys；
2，将文件Packet.dll，WanPacket.dll，wpcap.dll,pthreadVC.dll复制到system32中，将npf.sys复制到system32\drivers中；
3，将npf安装为驱动，以下是使用sc.exe的安装方法：
     sc create npf binpath= system32\drivers\npf.sys type= kernel start= demand
   你也可以使用其他工具；
4，卸载方法：先停止驱动npf（sc stop npf）,再删除驱动（sc delete npf）,最后删除上文提到的5个文件；
5，注意：该方法只对WinPcap3.1的文件进行了测试，其他版本请自己测试(最新测试4.0.2)；
         请明智的使用该方法，本人不承担任何法律责任。



ps:此目录中的setup.bat为安装脚本;del.bat为反安装脚本
    