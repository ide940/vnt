#!/bin/sh

sz="$@"

if [ -z "${sz}" ] ; then
echo "去除#号可运行"
logger "去除#号可运行"
test ! -z `pidof vnt-cli` && killall vnt-cli
exit
fi
##vnt-cli 上无参数，退出运行
test -z "`sysctl -a | grep 'net.ipv4.ip_forward = 1'`" && sysctl -w net.ipv4.ip_forward=1 && (logger "开启系统内核转发功能";echo "开启系统内核转发功能" ) 

if [  -f "/etc/storage/started_script.sh" ] ;then
test -n "`ps |grep 'crond'|grep '\-d10'|grep -v grep|awk '{print $1}'`" || (killall crond && /usr/sbin/crond -d10)
fi

if iptables -t nat ! -C POSTROUTING -j MASQUERADE &>/dev/null; then
iptables -t nat -I POSTROUTING  -j MASQUERADE   
fi

test -z "`iptables -vnL |grep vnt-tun`" && (iptables -I FORWARD -o vnt-tun -j ACCEPT;iptables -I FORWARD -i vnt-tun -j ACCEPT;iptables -I INPUT -i vnt-tun -j ACCEPT)

if [ -z "$(echo "${sz}"|grep \+s )" ] ; then
##判断参数中是否无“+s”
s=""
else
	ip4p=`echo "${sz}"|awk -v RS='+'  '{print $0}'|grep 's'|grep -v 'k' |awk '{print $2}'`
##将参数中的“+”断点进行分行，查找有“s”的行，并排除“k”的行，打印第二列
	eval $(nslookup ${ip4p} 119.29.29.29 | awk '/2001/' |cut -d ':' -f 2-6 | awk -F: '{print "port="$3" ipa="$4" ipb="$5 }')
##查询域名，并提取出ip4p地址
	port=$((0x$port))
	ip1=$((0x${ipa:0:2}))
	ip2=$((0x${ipa:2:2}))
	ip3=$((0x${ipb:0:2}))
	ip4=$((0x${ipb:2:2}))
	ipv4="${ip1}.${ip2}.${ip3}.${ip4}:${port}"
	lastIP="$(cat /tmp/natmat-vnts-ip4p.txt)"
	#检查ip是否变动
		if [ "$lastIP" != "$ipv4" ] ; then
		killall vnt-cli
		echo ${ip1}.${ip2}.${ip3}.${ip4}:${port} >/tmp/natmat-vnts-ip4p.txt
		ip="${ip1}.${ip2}.${ip3}.${ip4}:${port}"
		fi
	s="-s ${ipv4}"
fi
##增加了支持ip4p地址

test -f "/tmp/vnt_tmp" && vnt_tmp2=$(tail -n 1 "/tmp/vnt_tmp") || vnt_tmp2="::"
if [ "${sz}" == "${vnt_tmp2}" ] && [ ! -z `pidof vnt-cli` ]  ; then
exit
fi
##参数相同并在运行中，退出运行

echo "${sz}" >> /tmp/vnt_tmp
##将参数记录到临时文件中
:<<!
test -f "/usr/bin/vnt-cli" && vnt="/usr/bin/vnt-cli"
test -f "/etc/storage/vnt-cli" && vnt="/etc/storage/vnt-cli"
test -f "/etc/storage/bin/vnt-cli" && vnt="/etc/storage/bin/vnt-cli"
test -f "/etc/vnt-cli" && vnt="/etc/vnt-cli"
test -f "/tmp/vnt-cli" && vnt="/tmp/vnt-cli" 

##查找vnt-cli文件
if [ ! -f "/etc/storage/vnt-cli" ] && [ ! -f "/etc/vnt-cli" ] && [ ! -f "/etc/storage/bin/vnt-cli" ] && [ ! -f "/tmp/vnt-cli" ] && [ ! -f "/usr/bin/vnt-cli" ] ; then
##上述目录都不存在vnt-cli
!

SCRIPT_DIR="$(cd $(dirname $0); pwd)"
echo "脚本所在目录: $SCRIPT_DIR"

if [ -f "${SCRIPT_DIR}/vnt_cli_set_dir.txt" ] && [ -f "$(tail -n 1 ${SCRIPT_DIR}/vnt_cli_set_dir.txt)/vnt-cli" ] ; then
	vnt="$(tail -n 1 ${SCRIPT_DIR}/vnt_cli_set_dir.txt)/vnt-cli"
	 [ ! -x "${vnt}" ] && chmod +x "${vnt}"
if	 [ 3 -gt $(($(${vnt} -h | wc -l))) ] ;then 
 mv "$(tail -n 1 ${SCRIPT_DIR}/vnt_cli_set_dir.txt)/vnt-cli" "$(tail -n 1 ${SCRIPT_DIR}/vnt_cli_set_dir.txt)/vnt0-cli" 
vnt="" 
fi
# 检查是否可运行，否则重名，下一步去下载
else
	vnt_path="/tmp /etc /usr /etc/storage"   # 设定多个路径

	for v in ${vnt_path}
	do
		echo "在目录$v查找"
		vnt_cli_tmp=$(find "$v" -type f -name "vnt-cli" )
		yes1=$?
		if [[ ${yes1} = 0 ]] ; then # 判断是否有vnt-cli ，有为0，没有为其他数字
			vnt_cli_psc=$(echo "${vnt_cli_tmp}" | wc -l) # 统计有多少个vnt-cli
			echo "$v目录中有${vnt_cli_psc}个文件（vnt-cli）" 
			for y in $(seq 1 $vnt_cli_psc)
			do
				vnt=$(echo "${vnt_cli_tmp}" | awk 'NR=='"$y"'{print $0}') # 第y行的vnt_cli文件
				[ ! -x "${vnt}" ] && chmod +x "${vnt}" # 判断vnt-cli是否有执行权限
				if [ $(($(${vnt} -h | wc -l))) -gt 3 ]; then # 判断vnt-cli是否可正常运行
					yes=$?
					echo "正常运行" 
					break # 跳出y循环
				fi
			done

			if [[ ${yes1} = 0 ]] &&  [[ ${yes} = 0 ]] ; then
				break  # 跳出v循环
			fi
		fi
	done

fi
echo "${vnt}"

if [ "${vnt}" = "" ] ; then

vnt="/tmp/vnt-cli" 

cputype=$(uname -ms | tr ' ' '_' | tr '[A-Z]' '[a-z]')
[ -n "$(echo $cputype | grep -E "linux.*armv.*")" ] && cpucore="arm"
[ -n "$(echo $cputype | grep -E "linux.*armv7.*")" ] && [ -n "$(cat /proc/cpuinfo | grep vfp)" ] && [ ! -d /jffs/clash ] && cpucore="armv7"
[ -n "$(echo $cputype | grep -E "linux.*aarch64.*|linux.*armv8.*")" ] && cpucore="aarch64"
[ -n "$(echo $cputype | grep -E "linux.*86.*")" ] && cpucore="i386"
[ -n "$(echo $cputype | grep -E "linux.*86_64.*")" ] && cpucore="x86_64"
if [ -n "$(echo $cputype | grep -E "linux.*mips.*")" ] ; then
mipstype=$(echo -n I | hexdump -o 2>/dev/null | awk '{ print substr($2,6,1); exit}') ##通过判断大小端判断mips或mipsle
[ "$mipstype" = "0" ] && cpucore="mips" || cpucore="mipsle"
fi
 case "${cpucore}" in 
	"mipsle") curl -o "${vnt}" --connect-timeout 10 --retry 3 https://gh.con.sh/https://raw.githubusercontent.com/ide940/vnt/main/vnt-cli_mipsle
	;;
	"mips")  curl -o "${vnt}" --connect-timeout 10 --retry 3 https://gh.con.sh/https://raw.githubusercontent.com/ide940/vnt/main/vnt-cli_mips
	;;
	"x86_64")  curl -o "${vnt}" --connect-timeout 10 --retry 3 https://gh.con.sh/https://raw.githubusercontent.com/ide940/vnt/main/vnt-cli_x86_64
	;;
	"i386")  curl -o "${vnt}" --connect-timeout 10 --retry 3 https://gh.con.sh/https://raw.githubusercontent.com/ide940/vnt/main/vnt-cli_i386
	;;
	"arm")  curl -o "${vnt}" --connect-timeout 10 --retry 3 https://gh.con.sh/https://raw.githubusercontent.com/ide940/vnt/main/vnt-cli_arm
	;;
	"armv7")  curl -o "${vnt}" --connect-timeout 10 --retry 3 https://gh.con.sh/https://raw.githubusercontent.com/ide940/vnt/main/vnt-cli_armv7
	;;
	"aarch64")  curl -o "${vnt}" --connect-timeout 10 --retry 3 https://gh.con.sh/https://raw.githubusercontent.com/ide940/vnt/main/vnt-cli_aarch64
	;;
esac
##判断CPU框架并下载对应的执行文件

test ! -x "${vnt}" && chmod +x "${vnt}"
 [ $(($(${vnt} -h | wc -l))) -gt 3 ] || rm -rf "${vnt}"
##判断执行文件是否可运行,否则删除
	if [ -f "${SCRIPT_DIR}/vnt_cli_set_dir.txt" ] && [ -d "$(tail -n 1 ${SCRIPT_DIR}/vnt_cli_set_dir.txt)" ] ; then
		cp "${vnt}" "$(tail -n 1 ${SCRIPT_DIR}/vnt_cli_set_dir.txt)"
	vnt="$(tail -n 1 ${SCRIPT_DIR}/vnt_cli_set_dir.txt)/vnt-cli"
	else
		if [ ! -z "`uname -a | tr [A-Z] [a-z]|grep -o wrt`" ] ;then
			size=`df -k |awk '/\/overlay$/{sub(/K$/,"",$4);print $4}'`
			test "${size}" -gt 1000 && cp "${vnt}" /etc/
	##判断系统是否为openwrt，若是并空间大于1000时就把vnt-cli文件复制到etc目录中
		fi
		if [  -d "/etc/storage" ] ;then
			size=`df -k |awk '/\/etc$/{sub(/K$/,"",$4);print $4}'|tr -d '.'|tr -d 'M'`
			test "${size}" -gt 10 && cp "${vnt}" /etc/storage
	##判断系统是否为padavan，若是并空间大于10时就把vnt-cli文件复制到storage目录中
		fi
	fi
fi
test ! -z "`uname -a | tr [A-Z] [a-z]|grep -o wrt`" &&  test -z "`opkg list-installed|grep kmod-tun`" && opkg update && opkg install kmod-tun
##判断openwrt有无安装tun模块，无就进行安装
test ! -x "${vnt}" && chmod +x "${vnt}"
##判断文件有无执行权限，无赋予运行权限

if [ -n "$(echo "${sz}"|grep '\-n')" ] ; then
n=""
else
n1="-n `uname -nms|tr [\ ] [_]`"
n="${n1}"
fi
##判断设备名称

if [ -n "$(echo "${sz}"|grep '\-d')" ] ; then
d=""
else
d1="-d `echo "${sz}"|awk -v RS='-'  '{print $0}'|grep ip |awk '{print $2}'|awk -F'.' '{print $4}'`"
d="${d1}"
fi
##判断参数上有无-d,无则用ip最后数字


[  -n "`pidof vnt-cli`" ] && "${vnt}" --stop && killall vnt-cli
##先退出旧运行参数的进程
sleep 2

"${vnt}" $@ --no-proxy ${d} ${n} ${s} >/tmp/vnt-cli.log 2>&1  &
##这是个脚本的核心
sleep 2

echo  -n "$(date +%s)" > /tmp/start_timestamp_vnt_cli


[  -z `pidof vnt-cli` ] && echo "运行失败" || echo "${vnt}  ${d} ${sz} ${n} --no-proxy & 运行成功"
[  -z `pidof vnt-cli` ] && logger "运行失败" || logger "${vnt}  ${d} ${sz} ${n} --no-proxy & 运行成功"

