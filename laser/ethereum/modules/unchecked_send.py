def execute(svm):

	for k in svm.nodes:
		node = svm.nodes[k]

		for instruction in node.instruction_list:
			if(instruction['opcode'] == "PUSH1"):
				state = node.states[instruction['address']]

				print(instruction['opcode'] + " - " + str(state.as_dict))
