#! /bin/bash

echo "Starting monitoring traffic"
for file in *.pcap
do
	sudo chmod 777 "${file}"
	echo "${file}"
	a=$(python3 periodDetector.py --pcap "${file}" 2> /dev/null)
	echo "${a}"

	if [ $a = "1" ]
	then
		echo "There is an attack in that period"
		# Split the abnormal pcap file of period into each pcap file of flow
		mono SplitCap.exe -r "${file}" -o flow_detection -s flow
		sleep 2
		cd flow_detection
		for file1 in *.pcap
		do
			echo "Detecting abnormal flow"
			sudo chmod 777 "${file1}"
			isAbnormalflow=$(python3 flowDetector.py --pcap "${file1}" 2> /dev/null)
			echo "${isAbnormalflow}"
			rm "${file1}"
		done
		cd ..
	else
		echo "This is a normal period"
	fi
	rm "${file}"
done

