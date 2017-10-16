import graphviz as gv
from z3 import *
import re

styles = {
    'graph': {
        'overlap': 'false',
        'fontsize': '12',
        'fontcolor': 'white',
        'bgcolor': '#333333',
        'concentrate':'true',
    },
    'nodes': {
        'fontname': 'Helvetica',
        'fontsize': '12',
        'shape': 'box',
        'fontcolor': 'white',
        'color': 'white',
        'style': 'filled',
        'fillcolor': '#009966',
    },
    'edges': {
        'style': 'dashed',
        'dir': 'forward',
        'color': 'white',
        'arrowhead': 'normal',
        'fontname': 'Courier',
        'fontsize': '12',
        'fontcolor': 'white',
    }
}

def apply_styles(graph, styles):
    graph.graph_attr.update(
        ('graph' in styles and styles['graph']) or {}
    )
    graph.node_attr.update(
        ('nodes' in styles and styles['nodes']) or {}
    )
    graph.edge_attr.update(
        ('edges' in styles and styles['edges']) or {}
    )
    return graph


def generate_callgraph(svm, file):

    graph = gv.Graph(format='svg')

    for key in svm.nodes:
        node_text = ""

        for instruction in svm.nodes[key].instruction_list:
            node_text += str(instruction['address']) + " " + instruction['opcode']
            if instruction['opcode'].startswith("PUSH"):
                node_text += " " + instruction['argument']

            node_text += "\l"


        graph.node(str(key), node_text)

    for edge in svm.edges:

        if (edge.condition is None):
            expression = ""
        else:

            try:
                expression = str(simplify(edge.condition))
            except Z3Exception:
                expression = str(edge.condition)

            expression = re.sub("(\d+)",  lambda m: hex(int(m.group(1))), expression)
            expression = re.sub("[0]{8}[0]+", "0000(...)", expression)
            expression = re.sub("[f]{8}[f]+", "ffff(...)", expression)

            '''
            s = Solver()
            s.add(edge.condition)

            if ("BoolRef" in str(type(edge.condition))):
                s.add(edge.condition)
            else:
                s.add(edge.condition == 1)

            if (s.check() == sat):

                m = s.model()

                solution = str(m)
                solution = re.sub("(\d+)",  lambda m: hex(int(m.group(1))), solution)
                solution = re.sub("[0-9a-f]{32}[\],\)]*", "(...)", solution)
            else:
                solution = "unsat"
            '''

        graph.edge(str(edge.node_from),str(edge.node_to), expression)

    graph = apply_styles(graph, styles)

    graph.render(file)

