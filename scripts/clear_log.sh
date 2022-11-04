#! /bin/bash

threshold=1000000
cd /var/log/
for i in `seq 1 10`
do
    # echo $i
    rm -f *"."$i
    rm -f *"."$i"."*
    rm -f *"."$i"."log
done

du -sh /var/log | awk '{ print $1}' | grep G
if [ $? -eq 0 ]; then
	check=$(du -sh /var/log | awk '{ print $1}' | grep G | cut -d '.' -f1 )
	echo $check
	if [ $check -gt 1 ]; then
		for FILENAME in `ls`; do
			if [ -f $FILENAME ]; then
				SIZE=$(du -sb $FILENAME | awk '{ print $1 }')
				if [ $SIZE -gt $threshold ] ; then
						cat /dev/null > $FILENAME
				else
						echo "File $FILENAME less";
				fi
			else
				echo "$FILENAME is Folder"
				cd $FILENAME
				for FILE in `ls`; do
					if [ -f $FILE ]; then
						SIZE=$(du -sb $FILE | awk '{ print $1 }')
						if [ $SIZE -gt $threshold ] ; then
								cat /dev/null > $FILE
						else
								echo "File $FILE less";
						fi
					fi	
				done
			fi
		done
	fi
else
    echo "Folder log nho hon 1 Gb"
fi
