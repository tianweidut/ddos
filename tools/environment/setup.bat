copy *.dll %windir%\system32\
copy npf.sys %windir%\system32\drivers\
sc create npf binpath=system32\drivers\npf.sys type= kernel start= demand
echo 安装完成
pasue