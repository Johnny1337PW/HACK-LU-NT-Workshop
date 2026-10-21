# HACK.LU Internet Background Radiation: Exploiting the Void


**Universal handout — no credentials included. Your personal username and password are on your printed card.**

## Important notice


**Important:** `source_ip` and `destination_ip` values were anonymized with **CryptoPAN** before publication. This prevents direct correlation with external information sources, but it keeps the internal subnet logic and address relationships intact within the telescope dataset.


- **Host:** `fb4e0g1ih4.eu-central-1.aws.clickhouse.cloud`
- **Username:** `<your_username>`
- **Password:** `<your_password>`
- **Database:** `default`


## Server idle / wake-up note

The ClickHouse Cloud instance enters an idle state after about 15 minutes without user activity. It can be woken up by a normal connection attempt from the `clickhouse-client`, which may take up to about 2 minutes while the service resumes from its idle state.


The instance is scaled dynamically. If a query hits memory or other resource limits, please wait for the service to scale or free resources before retrying. The maximum memory allocation per query is **24 GiB**. If you need more than that for a specific task, please contact the workshop organizers personally or after at **jan.adamski@nask.pl**, **jakub.koman@nask.pl**, **pawel.pawlinski@cert.pl**, or **paul.jung@circl.lu**.


## Connect with clickhouse-client

Install `clickhouse-client` on your computer. Run the following command, replacing the placeholders with your personal credentials:


```bash
clickhouse-client --host fb4e0g1ih4.eu-central-1.aws.clickhouse.cloud --secure --user <your_username> --password '<your_password>'
```


If the service has been idle for 15 minutes, the server may enter an idle state. A normal connection attempt from the ClickHouse client can wake it up; the wake-up may take up to 2 minutes before the connection becomes fully ready.


## Access and rules

Read-only (`SELECT`) access is granted to three tables in the `default` database. Maximum memory per query: **24 GiB**; maximum query threads: **4**. This script does not impose additional query time, row-read, or result-size limits. Service-wide limits may still apply.


## Data coverage and anonymization


**Covered data windows:**


- `default.tcp_events`: 01.09–30.09.2026


- `default.udp_events`: 01.09–10.09.2026


- `default.udp_payloads`: 01.09–10.09.2026



## Table field descriptions


**Note:** TCP and UDP fields are documented separately, including fields with identical names. Interpretations of pipeline-specific classifications (`event_type`, `port_expert`, `pgahex`, `tool_signature`, etc.) should be validated against the actual data-processing code.


### `default.tcp_events` (01.09–30.09.2026)


| Column | Type | Description |
|---|---|---|
| `protocol` | LowCardinality(String) | Transport protocol recorded for the event. |
| `pcap_name` | String | Name of the source PCAP capture file. |
| `uuid` | UUID | Unique event identifier. |
| `source_ip` | IPv4 | Source IPv4 address observed by the network telescope. |
| `event_type` | LowCardinality(String) | TCP event category assigned by the TCP event classifier: Scan/Backscatter, DoS |
| `event_subtype` | LowCardinality(String) | SYN,PSH+ACK,SYN-ACK,RST+ACK,RST,FIN,ACK,MAIMON,XMAS_STH,OTHER,XMAS_NMAP,NULL,XMAS,ALL |
| `event_scope` | LowCardinality(String) | Scope assigned to a TCP event - Horizontal, Vertical, Box, Single |
| `destination_ip_count` | UInt32 | Number of distinct destination IPv4 addresses associated with the event; check aggregation semantics before interpreting. |
| `destination_ip` | Nullable(IPv4) | Destination IPv4 address when uniquely attributable to the event; otherwise NULL. |
| `hit_subnets` | Map(LowCardinality(String), UInt32) | Map of telescope subnet labels to observed hit counts. |
| `start_time` | DateTime64(3, 'Europe/Warsaw') | Timestamp of the first observation in the event (Europe/Warsaw, millisecond precision). |
| `stop_time` | DateTime64(3, 'Europe/Warsaw') | Timestamp of the last observation in the event (Europe/Warsaw, millisecond precision). |
| `packet_count` | UInt32 | Total number of packets attributed to this event. |
| `byte_count` | UInt64 | Total bytes attributed to this event. |
| `reassembled_packets` | UInt32 DEFAULT 0 | Count of packets associated with reassembly, as reported by the processing pipeline. |
| `packets_time_interval` | LowCardinality(String) | Pipeline-derived descriptor of inter-packet time intervals. |
| `ttl` | Map(LowCardinality(String), UInt32) | Frequency map of observed IP Time To Live (TTL) values. |
| `tos_expert` | Map(LowCardinality(String), UInt32) | Frequency map of observed or classified IPv4 Type of Service / DSCP values. |
| `ttl_type` | Nullable(Enum8('ttl_constant' = 1, 'ttl_incremental' = 2)) | TTL behavior classification: constant, incremental, or NULL when unclassified. |
| `window_size` | Map(LowCardinality(String), UInt32) | Frequency map of TCP advertised window sizes. |
| `source_ports` | Map(LowCardinality(String), UInt32) | Frequency map of observed source port values. |
| `destination_ports` | Map(LowCardinality(String), UInt32) | Frequency map of observed destination port values. |
| `pgahex` | Array(Tuple(key LowCardinality(String), count UInt32, percent UInt8, uniqueVals UInt32, mostCommonCnt UInt32, doubt UInt8)) | Per-feature PGAHEX summaries: key, count, percentage, unique value count, most common count, and uncertainty indicator. Key parsing available separately. |
| `tool_signature` | Map(LowCardinality(String), UInt32) | Counts of tool signatures detected by the processing pipeline. |
| `port_expert` | UInt8 | Pipeline-defined port classification or indicator; exact encoding is dataset-specific. 1 - Single port, 2 - Two ports, 3 up to 10 ports, 4 up to 1024 ports, 5 up to 32767, 6 up to 50000 |
| `l4_implementation` | LowCardinality(String) | Inferred transport-layer (L4) implementation or fingerprint. |
| `tcp_flags` | FixedString(8) | Eight-character representation of the observed TCP flags, using the pipeline encoding. |
| `ip_uncommon_header_length` | UInt32 DEFAULT 0 | Count of packets with an unusual IPv4 header length. |
| `ip_null_bit_set` | UInt32 DEFAULT 0 | Count of packets with an unexpected IPv4 header bit set. |
| `ip_df_flag_set` | UInt32 DEFAULT 0 | Count of packets with the IPv4 Don’t Fragment (DF) flag set. |
| `ip_mf_flag_set` | UInt32 DEFAULT 0 | Count of packets with the IPv4 More Fragments (MF) flag set. |
| `cwr_flag_set` | UInt32 DEFAULT 0 | Count of TCP packets with CWR set. |
| `ece_flag_set` | UInt32 DEFAULT 0 | Count of TCP packets with ECE set. |
| `ip_fragment_offset_set` | UInt32 DEFAULT 0 | Count of packets with a nonzero IPv4 fragment offset. |
| `ip_checksum_invalid` | UInt32 DEFAULT 0 | Count of packets with an invalid IPv4 header checksum. |
| `ip_id_expert_const_count` | UInt32 DEFAULT 0 | Count of observations consistent with a constant IPv4 Identification field. |
| `ip_id_expert_const_growth_count` | UInt32 DEFAULT 0 | Count of observations consistent with fixed-step growth in IPv4 Identification. |
| `ip_id_expert_const_growth_step` | UInt16 DEFAULT 0 | Detected increment step for the IPv4 Identification field. |
| `ip_id_expert_mono_inc_count` | UInt32 DEFAULT 0 | Count of observations with monotonically increasing IPv4 Identification. |
| `ip_id_expert_bitmask_value` | LowCardinality(String) DEFAULT '' | Detected bitmask pattern of the IPv4 Identification field. |
| `ip_id_expert_bitmask_count` | UInt32 DEFAULT 0 | Count of matches for the IPv4 Identification bitmask pattern. |
| `ack_invalid` | UInt32 DEFAULT 0 | Count of TCP ACK anomalies (Flag set, empty ACK number field, and opposite) flagged by the analyzer. |
| `reserved_bits_non_zero` | UInt32 DEFAULT 0 | Count of TCP packets with nonzero reserved bits. |
| `constant_window_size` | UInt32 DEFAULT 0 | Count of occurrences of a constant TCP window size. |
| `urgent_pointer_non_zero` | UInt32 DEFAULT 0 | Count of TCP packets with a nonzero urgent pointer. |
| `tcp_checksum_invalid` | UInt32 DEFAULT 0 | Count of packets with an invalid TCP checksum. |
| `uncommon_offset` | Map(LowCardinality(String), UInt32) | Frequency map of unusual TCP header data-offset values. |
| `tcpopt_raw` | String | Raw representation of TCP header options. |
| `seq_const_growth_count` | UInt32 DEFAULT 0 | Count of instances of constant-step TCP sequence number growth. |
| `seq_const_growth_step` | UInt32 DEFAULT 0 | Detected step for constant-step TCP sequence number growth. |
| `seq_mono_inc_count` | UInt32 DEFAULT 0 | Count of instances of monotonically increasing TCP sequence numbers. |
| `seq_constant_count` | UInt32 DEFAULT 0 | Count of observations of constant TCP sequence numbers. |
| `seq_bitmask_value` | LowCardinality(String) DEFAULT '' | Detected TCP sequence-number bitmask pattern. |
| `seq_bitmask_count` | UInt32 DEFAULT 0 | Count of matches to the TCP sequence-number bitmask pattern. |
| `seq_pattern_length` | UInt32 DEFAULT 0 | Length of the detected TCP sequence-number pattern. |
| `seq_pattern_step` | UInt32 DEFAULT 0 | Step of the detected TCP sequence-number pattern. |
| `seq_pattern_repeats` | UInt32 DEFAULT 0 | Number of repeats of the detected TCP sequence-number pattern. |
| `seq_pattern_count` | UInt32 DEFAULT 0 | Number of matches to the detected TCP sequence-number pattern. |
| `targeted_services` | Map(LowCardinality(String), UInt32) | Map of inferred targeted services to counts. |


### `default.udp_events` (01.09–10.09.2026)


| Column | Type | Description |
|---|---|---|
| `protocol` | LowCardinality(String) | Transport protocol recorded for the event. |
| `pcap_name` | String | Name of the source PCAP capture file. |
| `uuid` | UUID | Unique event identifier. |
| `source_ip` | IPv4 | Source IPv4 address observed by the network telescope. |
| `event_type` | LowCardinality(String) | Scan/DoS |
| `event_subtype` | LowCardinality(String) | UDP highest layer protocol |
| `event_scope` | LowCardinality(String) | Scope assigned to a UDP event - Horizontal, Vertical, Box, Single |
| `destination_ip_count` | UInt32 | Number of distinct destination IPv4 addresses associated with the event; check aggregation semantics before interpreting. |
| `destination_ip` | Nullable(IPv4) | Destination IPv4 address when uniquely attributable to the event; otherwise NULL. |
| `hit_subnets` | Map(LowCardinality(String), UInt32) | Map of telescope subnet labels to observed hit counts. |
| `start_time` | DateTime64(3, 'Europe/Warsaw') | Timestamp of the first observation in the event (Europe/Warsaw, millisecond precision). |
| `stop_time` | DateTime64(3, 'Europe/Warsaw') | Timestamp of the last observation in the event (Europe/Warsaw, millisecond precision). |
| `packet_count` | UInt32 | Total number of packets attributed to this event. |
| `byte_count` | UInt64 | Total bytes attributed to this event. |
| `reassembled_packets` | UInt32 DEFAULT 0 | Count of packets associated with reassembly, as reported by the processing pipeline. |
| `packets_time_interval` | LowCardinality(String) | Pipeline-derived descriptor of inter-packet time intervals. |
| `ttl` | Map(LowCardinality(String), UInt32) | Frequency map of observed IP Time To Live (TTL) values. |
| `tos_expert` | Map(LowCardinality(String), UInt32) | Frequency map of observed or classified IPv4 Type of Service / DSCP values. |
| `ttl_type` | Nullable(Enum8('ttl_constant' = 1, 'ttl_incremental' = 2)) | TTL behavior classification: constant, incremental, or NULL when unclassified. |
| `source_ports` | Map(LowCardinality(String), UInt32) | Frequency map of observed source port values. |
| `destination_ports` | Map(LowCardinality(String), UInt32) | Frequency map of observed destination port values. |
| `pgahex` | Array(Tuple(key LowCardinality(String), count UInt32, percent UInt8, uniqueVals UInt32, mostCommonCnt UInt32, doubt UInt8)) | Per-feature PGAHEX summaries: key, count, percentage, unique value count, most common count, and uncertainty indicator. Key parsing available separately. |
| `tool_signature` | Map(LowCardinality(String), UInt32) | Counts of tool signatures detected by the processing pipeline. |
| `l4_implementation` | LowCardinality(String) | Inferred transport-layer (L4) implementation or fingerprint. |
| `highest_layer_protocol` | LowCardinality(String) | Highest-level protocol recognized in the UDP traffic. |
| `payload_clusters` | Array(Int32) | Identifiers of payload clusters associated with the UDP event. |
| `port_expert` | UInt8 | Pipeline-defined port classification or indicator; exact encoding is dataset-specific. 1 - Single port, 2 - Two ports, 3 up to 10 ports, 4 up to 1024 ports, 5 up to 32767, 6 up to 50000 |
| `ip_uncommon_header_length` | UInt32 DEFAULT 0 | Count of packets with an unusual IPv4 header length. |
| `ip_null_bit_set` | UInt32 DEFAULT 0 | Count of packets with an unexpected IPv4 header bit set. |
| `ip_df_flag_set` | UInt32 DEFAULT 0 | Count of packets with the IPv4 Don’t Fragment (DF) flag set. |
| `ip_mf_flag_set` | UInt32 DEFAULT 0 | Count of packets with the IPv4 More Fragments (MF) flag set. |
| `ip_fragment_offset_set` | UInt32 DEFAULT 0 | Count of packets with a nonzero IPv4 fragment offset. |
| `ip_checksum_invalid` | UInt32 DEFAULT 0 | Count of packets with an invalid IPv4 header checksum. |
| `ip_id_expert_const_count` | UInt32 DEFAULT 0 | Count of observations consistent with a constant IPv4 Identification field. |
| `ip_id_expert_const_growth_count` | UInt32 DEFAULT 0 | Count of observations consistent with fixed-step growth in IPv4 Identification. |
| `ip_id_expert_const_growth_step` | UInt16 DEFAULT 0 | Detected increment step for the IPv4 Identification field. |
| `ip_id_expert_mono_inc_count` | UInt32 DEFAULT 0 | Count of observations with monotonically increasing IPv4 Identification. |
| `ip_id_expert_bitmask_value` | LowCardinality(String) DEFAULT '' | Detected bitmask pattern of the IPv4 Identification field. |
| `ip_id_expert_bitmask_count` | UInt32 DEFAULT 0 | Count of matches for the IPv4 Identification bitmask pattern. |
| `wrong_port` | UInt32 DEFAULT 0 | Count of unusual or mismatched UDP ports detected by the analyzer. |
| `packet_lengths` | Map(LowCardinality(String), UInt32) | Frequency map of UDP packet lengths. |
| `udp_checksum_invalid` | UInt32 DEFAULT 0 | Count of packets with an invalid UDP checksum. |
| `protocol_stack` | LowCardinality(String) DEFAULT '' | Identified protocol stack for the UDP event. |
| `avg_payload_entropy` | Float32 DEFAULT 0 | Mean entropy of UDP payloads associated with the event. |
| `max_payload_entropy` | Float32 DEFAULT 0 | Maximum entropy of UDP payloads associated with the event. |
| `min_payload_entropy` | Float32 DEFAULT 0 | Minimum entropy of UDP payloads associated with the event. |
| `avg_payload_size` | Float32 DEFAULT 0 | Mean UDP payload size in bytes. |
| `max_payload_size` | UInt32 DEFAULT 0 | Maximum UDP payload size in bytes. |
| `min_payload_size` | UInt32 DEFAULT 0 | Minimum UDP payload size in bytes. |
| `unique_payloads` | UInt32 DEFAULT 0 | Number of distinct payloads associated with the UDP event. |


### `default.udp_payloads` (01.09–10.09.2026)


| Column | Type | Description |
|---|---|---|
| `date` | Date | Calendar date used to group payload observations. |
| `first_seen` | DateTime64(6, 'UTC') | Timestamp of the first observation of this payload group (UTC, microsecond precision). |
| `last_seen` | DateTime64(6, 'UTC') | Timestamp of the last observation of this payload group (UTC, microsecond precision). |
| `src_ip` | IPv4 | Source IPv4 address associated with the payload group. |
| `dst_ips` | Map(IPv4, UInt64) | Map of destination IPv4 addresses to packet counts for this payload group. |
| `src_ports` | Map(UInt16, UInt64) | Map of UDP source ports to packet counts for this payload group. |
| `dst_ports` | Map(UInt16, UInt64) | Map of UDP destination ports to packet counts for this payload group. |
| `prot` | LowCardinality(String) | Transport protocol label, typically udp. |
| `hash` | UInt64 | 64-bit hash used to identify or group a payload |
| `payload` | String | Payload content |
| `len` | UInt32 | Payload length in bytes. |
| `entropy` | Float32 | Entropy of the payload content. |
| `coding` | LowCardinality(String) | Detected encoding or content format of the payload. |
| `hlp` | LowCardinality(String) | Identified higher-level protocol for the payload. |
| `packet_count` | UInt64 | Number of packets aggregated into this payload record. |



## Appendix: how to read `pgahex` relation codes


The `pgahex` array in `tcp_events`/`udp_events` stores header-field relations detected by the processing pipeline. Each tuple is `(key String, count UInt32, percent UInt8, uniqueVals UInt32, mostCommonCnt UInt32, doubt UInt8)`; the `key` is the 16-character hex encoding of a 64-bit big-endian `relationCode`, followed by the relation statistics.


### `relationCode` layout (big-endian bytes `[0]`–`[7]`)


| Byte | Meaning |
|---|---|
| `[0]` | Relation type |
| `[1]` | Modifier 1 `m` (e.g. shift width, increment step) |
| `[2]` | Compound relation second step (e.g. increment after bit-shift) |
| `[3]` | Modifier 2 `m2` |
| `[4]` | Operand 1 (result) |
| `[5]` | Operand 2 |
| `[6]` | Operand 3 (3-operand relations only) |
| `[7]` | Operand length (`wlen`) and protocol code (`wlenProto`) |
Unused fields must be zero. Operands `1`–`3` are pipeline-specific field codes (e.g. `0x1d` = `tcp_ack[1]`, `0x1f` = `tcp_ack[3]`).


**Worked example** — `tcp_ack : 1 : = << 2 + 2 : tcp_ack : 3` becomes `0x010203021d1f0010`: bytes `[01]=Lshift`, `[02]=m=2`, `[03]=Increment`, `[02]=m2=2`, `[1d]=[1f]=tcp_ack` octets, `[00]=unused Op3`, `[10]=wlen u8 (0x01<<4) | protoTCP (0x00)`.


### Relation types (`[0]`)


| Code | Name | Meaning |
|---|---|---|
| `0x00` | `RelEquality` | `Op1 == Op2` |
| `0x01` | `RelLshift` | `Op1 == Op2 << m` |
| `0x02` | `RelRshift` | `Op1 == Op2 >> m` |
| `0x03` | `RelIncrement` | `Op1 == Op2 + m` |
| `0x04` | `RelDecrement` | `Op1 == Op2 - m` (only as second step of compound relations) |
| `0x05` | `RelMultiply` | `Op1 == Op2 * m` |
| `0x06` | `RelNOT` | `Op1 == ^Op2` |
| `0x07` | `RelMultiplyModulo` | `Op1 == Op2 * m (mod 256^wlen)` |
| `0x20` | `RelConst` | `Op1 == m` (single octets only) |
| `0x21` | `RelVariable` | `Op1` takes `m` distinct values (single octets only) |
| `0x40` | `RelSum` | `Op1 == Op2 + Op3` |
| `0x41` | `RelXOR` | `Op1 == Op2 ^ Op3` |
| `0x42` | `RelAND` | `Op1 == Op2 & Op3` |
| `0x43` | `RelOR` | `Op1 == Op2 | Op3` |
| `0x44` | `RelNOR` | `Op1 == ^(Op2 | Op3)` |
| `0x45` | `RelNAND` | `Op1 == ^(Op2 & Op3)` |
| `0x80` | `RelZmap` | `IP_ID == 54321` — Zmap scanner fingerprint |
| `0x81` | `RelMasscan` | `IP_ID ^ IP_DST[2-3] ^ TCP_DPORT ^ TCP_SEQ[2-3] == 0` — Masscan scanner fingerprint |
| `0x82` | `RelMirai` | `IP_DST == TCP_SEQ` — Mirai botnet fingerprint (alias of `0000000010180040`) |


Compound relations chain two steps in byte `[0]`/`[2]`, e.g. `Lshift(0x01)` then `Increment(0x03)`, or `AND(0x42)+Increment(0x03)` written as `0x420003__`.


### Operand length and protocol (`[7]`)  — `wlenProto = wlen << 4 | proto`


| `wlen` | Meaning | | `proto` | Meaning |
|---|---|---|---|---|
| `0x01` | 8 bits (1 octet) | | `0x00` | TCP |
| `0x02` | 16 bits (2 octets) | | `0x01` | UDP |
| `0x04` | 32 bits (4 octets) | | `0x02` | ICMP |
| | | | `0x0f` | other/unsupported |
Example: UDP + 16-bit word = `0x02 << 4 | 0x01 = 0x21`.


### Relation statistics (remaining tuple fields)


| Field | Meaning |
|---|---|
| `count` | Total occurrences of the relation in the event |
| `percent` | `count` as a percentage of the event's packets |
| `uniqueVals` | Number of distinct values taken by the result (operand 1) |
| `mostCommonCnt` | Occurrences of the most frequent result value |
| `doubt` | Bitmask of relevance-reducing findings (see below) |
Example `'034b0000170b0012': [76, 95, 12, 20, 0]` — relation `ICMP: ICMP_CHECKSUM[1] == IP_CHECKSUM[1] + 75` seen in 76 packets (95% of the event), result takes 12 distinct values, the most common occurring 20 times, no doubts.


For very large events (over ~100 000 packets) the statistics are computed on a random sample of that size, not the whole event.


### `doubt` codes (bitmask, can combine)


| Code | Meaning |
|---|---|
| `0x01` | Relation count equals the count of the most frequent result value |
| `0x02` | Relation between fragments of the same field (e.g. octets 2 and 3 of the destination IP) |
| `0x04` | Relation between related fields (e.g. `IP_LEN` and `UDP_LEN`) |
| `0x08` | *(proposed)* statistic of a single octet (constancy/variability) |
Combined example: equal counts (`0x01`) and same-field fragments (`0x02`) give `doubt = 0x03`.


### Finding known scanner/botnet fingerprints


```sql
SELECT source_ip, fingerprint, rel_count,
       packet_count, event_scope
FROM (
    SELECT source_ip, packet_count, event_scope,
           pgahex.key AS fingerprint, pgahex.count AS rel_count
    FROM default.tcp_events
    WHERE start_time >= toDateTime('2026-09-03 00:00:00', 'Europe/Warsaw')
      AND start_time <  toDateTime('2026-09-04 00:00:00', 'Europe/Warsaw')
      AND hasAny(pgahex.key, ['8000000000050000',   -- RelZmap
                          '8100000000000000',     -- RelMasscan
                          '0000000010180040'])   -- RelMirai
)
ORDER BY rel_count DESC
LIMIT 10;
```


Fingerprint keys above are the conventional encodings of `RelZmap`, `RelMasscan` and `RelMirai`; verify against the actual data before relying on them.
