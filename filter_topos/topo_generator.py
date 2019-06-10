from __future__ import print_function
import sys
import argparse
import json
import copy


def main():
	parser = argparse.ArgumentParser()

	parser.add_argument(
		"-n", "--neighbours", default="1",
		help = "path to input file (read from stdin if omitted)")  

	args = vars(parser.parse_args())

	with open('topology.json', 'r') as f:
		topology = json.load(f)

	interfaces = topology["BorderRouters"]["br1-ff00_0_120-1"]["Interfaces"] 
	interface1 = interfaces["1"]

	#endOfRange = args["neighbours"] + 1
	for x in range(2,int(args["neighbours"])+1):
		interf = copy.deepcopy(interface1)
		ASNum = 0x120 + x
		interf["ISD_AS"] = "1-ff00:0:"+format(ASNum, 'x')
		interfaces.update({x : interf})

	with open(str(args["neighbours"])+'neighbour_topo.json', 'w') as f:
		json.dump(topology, f, indent=3)


if __name__ == "__main__":
	main()
