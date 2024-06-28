-- Dataset Summaries for Metrics

-- Cluster observations by time. Were you expecting many small clusters or a few large or ???
select
--# name: observation_times
time_bucket(INTERVAL '15 minutes', observation_ts) ObsTime, count(*) NumRows
from raw_pf group by all order by all
;

select
--# name: observation_count
count(*) Observations from raw_pf
;

-- Get raw data collection range, which means we need to ignore process data reconstructed from Windows logs, which are activitytype="refresh"
select
--# name: raw_data_range
	min(observation_ts) first_seen,
	max(observation_ts) last_seen,
from
	raw_pf
;


-- Process centric metrics and analytics

-- Summarize processes by start/term
select 
--# name: process_life_summary
	process_life_cd,
	count(distinct process_name) uniq_process_name, 
	count(*) num_processes, 
    -- use window function to calculate the pct of grand total.
	(num_processes / sum(num_processes) over (partition by grouping(process_life_cd)))*100 pct,
from
	process_life_v1
group by rollup (process_life_cd)
order by all
;


-- Summarize processes by hostname, start/term
select 
--# name: process_life_host_summary
	hostname,
	process_life_cd,
	count(distinct process_name) uniq_process_name, 
	count(*) num_processes, 
	num_processes / sum(num_processes) over (partition by grouping(hostname, process_life_cd), hostname) pct_of_host,
from
	process_life_v1
group by
	rollup (hostname, process_life_cd)
order by all
;

-- Get count of unique process names
select 
--# name: uniq_process_count
  count(distinct process_name) uniq_count, count(*) total_processes
from process
;
