import re
import matplotlib.pyplot as plt

def parse_protocol_output(file_path):
    with open(file_path, 'r') as f:
        data = f.read()

    # Split by size blocks
    blocks = re.split(r"=== Run with size=(\d+) ===", data)[1:]
    sizes = blocks[0::2]         # sizes as strings
    contents = blocks[1::2]      # corresponding text blocks

    protocol_data = {}

    for size_str, block in zip(sizes, contents):
        size = int(size_str)

        # Extract metrics for each run within the block
        # There are three runs per size; find all values
        client_times = [float(t) for t in re.findall(r"CLIENT COMPUTATION COST IS ([\d\.]+)s", block)]
        server_times_ms = [float(t) for t in re.findall(r"SERVER COMPUTATION COST IS ([\d\.]+)ms", block)]
        smart_times_us = [float(t) for t in re.findall(r"SMART CONTRACT COMPUTATION COST IS ([\d\.]+)µs", block)]
        offchain_bytes = [(int(b) /(1024 * 1024)) for b in re.findall(r"OFF-CHAIN COMMUNICATION COST: (\d+) bytes", block)]
        onchain_bytes = [int(b) for b in re.findall(r"ON-CHAIN COMMUNICATION COST: (\d+) bytes", block)]

        # Compute averages
        avg_client = sum(client_times) / len(client_times) if client_times else None
        avg_server = (sum(server_times_ms) / len(server_times_ms)) if server_times_ms else None
        avg_smart = (sum(smart_times_us) / len(smart_times_us) ) if smart_times_us else None
        avg_offchain = sum(offchain_bytes) / len(offchain_bytes) if offchain_bytes else None
        avg_onchain = sum(onchain_bytes) / len(onchain_bytes) if onchain_bytes else None

        protocol_data[size] = {
            'client_comp': avg_client,
            'smart_comp': avg_smart,
            'server_comp': avg_server,
            'offchain_comm': avg_offchain,
            'onchain_comm': avg_onchain
        }

    return protocol_data

if __name__ == "__main__":
    # Paths to the two protocol output files
    prot1 = parse_protocol_output('prot1_output.txt')
    prot2 = parse_protocol_output('prot2_output.txt')

    # Sort sizes
    sizes = sorted(prot1.keys())

    # Metrics to plot and their titles
    metrics = ['onchain_comm', 'offchain_comm', 'client_comp', 'server_comp', 'smart_comp']
    titles = {
        'onchain_comm': 'On-chain Communication (bytes)',
        'offchain_comm': 'Off-chain Communication (MB)',
        'client_comp': 'Client Computation (s)',
        'server_comp': 'Server Computation (ms)',
        'smart_comp': 'Smart Contract Computation (µs)'
    }

    # Generate one plot per metric
    for metric in metrics:
        plt.figure()
        # Protocol 1 data
        y1 = [prot1[s][metric] for s in sizes]
        # Protocol 2 data
        y2 = [prot2[s][metric] for s in sizes]

        plt.plot(sizes, y1, marker='o', label='Protocol 1')
        plt.plot(sizes, y2, marker='s', label='Protocol 2')
        plt.xlabel('Data Size (Bytes)')
        plt.ylabel(titles[metric])
        plt.title(f"{titles[metric]} vs Data Size")
        plt.legend()
        plt.grid(True)
        plt.xticks(sizes)
        #plt.show()
        plt.savefig(f"{titles[metric]}.pdf", format="pdf")
