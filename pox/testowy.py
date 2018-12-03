
def calc_costs(vertices, edges, source):
    """
    Computes cost of paths from source to all entities in network.
    Essentially Bellman-Ford algorythm.
    """
    # Step 1: initialize graph
    distance = {}
    predecessor = {}
    for v in vertices:
        distance[v] = 16 # inf
        predecessor[v] = None
    distance[source] = 0
    # Step 2: relax edges repeatedly
    for i in range (1,len(vertices)-1): # dla wszystkich wezlow
        for e in edges: # (u,v)
            if distance[e[0]] + 1 < distance[e[1]]:
                distance[e[1]] = distance[e[0]] + 1
                predecessor[e[1]] = e[0]
    return distance, predecessor

def get_path(dst, predecessor):
    path = [dst]
    while predecessor[dst]:
        path.append(predecessor[dst])
        dst = predecessor[dst]
    path.reverse()
    return path

if __name__ == '__main__':
    switches = ['00-00-00-00-00-08', '00-00-00-00-00-01', '00-00-00-00-00-02', '00-00-00-00-00-03', '00-00-00-00-00-04', '00-00-00-00-00-05', '00-00-00-00-00-06', '00-00-00-00-00-07']
    links = [('00-00-00-00-00-01', '00-00-00-00-00-05'), ('00-00-00-00-00-08', '00-00-00-00-00-07'), ('00-00-00-00-00-04', '00-00-00-00-00-08'), ('00-00-00-00-00-05', '00-00-00-00-00-06'), ('00-00-00-00-00-03', '00-00-00-00-00-01'), ('00-00-00-00-00-07', '00-00-00-00-00-08'), ('00-00-00-00-00-06', '00-00-00-00-00-05'), ('00-00-00-00-00-08', '00-00-00-00-00-04'), ('00-00-00-00-00-01', '00-00-00-00-00-02'), ('00-00-00-00-00-01', '00-00-00-00-00-03'), ('00-00-00-00-00-06', '00-00-00-00-00-07'), ('00-00-00-00-00-08', '00-00-00-00-00-02'), ('00-00-00-00-00-04', '00-00-00-00-00-03'), ('00-00-00-00-00-02', '00-00-00-00-00-08'), ('00-00-00-00-00-05', '00-00-00-00-00-01'), ('00-00-00-00-00-07', '00-00-00-00-00-06'), ('00-00-00-00-00-03', '00-00-00-00-00-04'), ('00-00-00-00-00-02', '00-00-00-00-00-01')]
    d,p = calc_costs(switches, links, '00-00-00-00-00-07')
    print("Distance from s1: ")
    print(d)
    print("predecessor of s1: ")
    print(p)
    path = get_path('00-00-00-00-00-03', p)
    print(path)