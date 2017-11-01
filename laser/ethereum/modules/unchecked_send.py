def execute(svm):

	for k in svm.nodes:
		node = svm.nodes[k]

		for instruction in node.instruction_list:
			# print(str(instruction))

			if(instruction['opcode'] == "DELEGATECALL"):
				state = node.states[instruction['address']]

				print(instruction['opcode'] + " - " + str(state.as_dict()))
