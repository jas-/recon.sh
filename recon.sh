#!/bin/bash

# Recon tool


# Ensure path is robust
PATH=$PATH:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin


###############################################
# User defined variables
###############################################

# FQDN of CVE data source
cve_assets_location="https://cve.mitre.org/data/downloads/allitems.csv.gz"

# Shodan.io API key
shodan_api_key=""

# Shodan FQDN base
shodan_uri="https://api.shodan.io/shodan/host/"

# VulDB API key
vuldb_api_key=""

# VulDB FQDN base
vuldb_uri="https://vuldb.com/?api"

# Time in days for cached copy of CVE data sources and lookups
cached_time=30

# Verbosity
verbose=0


###############################################
# Bootstrap the environement
###############################################

# Current working directory
cwd="$(dirname $0)"

# Define libraries, assets & reporting folders
lib_path=${cwd}/libs
assets_path=${cwd}/assets
reports_path=${cwd}/reports

# Error if the ${inc_path} doesn't exist
if [ ! -d "${lib_path}" ] ; then
  echo "Defined library path doesn't exist (${lib_path})" && exit 1
fi


# Include all .sh files found in ${lib_path}
for f in ${lib_path}/*.sh; do
  source ${f}
done


# Julian day of year
julian_datestamp=$(conv_date_to_jdoy | cut -d"." -f1)

# Timestamp (user friendly and julian day of year)
ts="$(date +%Y%m%d)-${julian_datestamp}"

# Build things if we need
[ ! -d ${assets_path} ] && mkdir -p ${assets_path}
[ ! -d ${reports_path} ] && mkdir -p ${reports_path}


###############################################
# Give the user some options
###############################################

while getopts "c:r:t:v" OPTION ; do
  case $OPTION in
    c) cached_time=$OPTARG ;;
    r) reports=($OPTARG) ;;
    t) targets=$OPTARG ;;
    v) verbose=1 ;;
    *) usage && exit 1 ;;
  esac
done


###############################################
# Normalize our targets or use local values
###############################################

# Normalize our targets
targets=($(determine_targets ${targets[@]}))

# Create a filter from targets
targets_filter="$(echo "${targets[@]}" | tr ' ' '|' | tr '_' ':')"

# If ${#targets[@]} is empty we should bail
if [ ${#targets[@]} -eq 0 ]; then
  echo "Error: Unable to determine/use supplied targets."
  exit 1
fi

# Was a report specified? If so use the address associated with it
[ ${#reports[@]} -gt 0 ] &&
  targets=($(echo "${reports[@]}" | tr ' ' '\n' | cut -d"-" -f2))

# Be loud?
[ ${verbose} -eq 1 ] &&
  echo "Info: Using ${targets[@]//_/:} as target(s)"


###############################################
# Generate or use cached copies of targets
###############################################

# Generate an array of existing shodan reports
[ ${#reports[@]} -eq 0 ] &&
  reports=($(find ${reports_path} -type f -name "shodan-*" 2>/dev/null | sort -n))

# Iterate our targets
for target in ${targets[@]}; do

  # Build a temporary array of possible reports matching our target
  reports_tmp=($(echo "${reports[@]}" |
    tr ' ' '\n' | grep ${target}))

  # Does a cached report exist for ${target}
  if [ ${#reports_tmp[@]} -gt 0 ]; then

    # Use the latest report for cached time comparison
    report="$(echo "${reports_tmp[@]}" |
      tr ' ' '\n' | sort -n | tail -1)"

    # Get the Julian Day of year from the filename
    report_ts=$(echo "${report}" | cut -d"-" -f4)

    # Skip if ${report} is <= ${cached_time}
    if [ $(compare_jdoy_dates ${julian_datestamp} ${report_ts} ${cached_time}) -eq 0 ]; then

      # Be loud?
      [ ${verbose} -eq 1 ] &&
        echo "Info: Found cached shodan data for ${target//_/:}..."

      # Add ${report} to our completed reports array
      shodan_completed+=("${report}")
      continue
    fi
  fi

  # Be loud?
  [ ${verbose} -eq 1 ] &&
    echo "Info: Searching for CPE data about ${target//_/:}..."

  # Execute scan request
  curl -s -X GET "${shodan_uri}/${target//_/:}?key=${shodan_api_key}" > ${reports_path}/shodan-${target}-${ts}

  # Keep track of what our completed reports
  shodan_completed+=("${reports_path}/shodan-${target}-${ts}")
done

# Be loud?
[ ${verbose} -eq 1 ] &&
  echo "Info: Using ${#shodan_completed[@]} report(s) to locate CPE data"


###############################################
# Generate CPE data from reports
###############################################

# Iterate our completed reports
for report in ${shodan_completed[@]}; do

  # Generate an array of CPE data per report
  cpes+=($(cat ${report} |
    jq -r '.data[] | to_entries | map(select(.key | match("cpe|ip_str";"i"))) | map(.value)' 2>/dev/null |
    awk '$1 ~ /"/' | sed 's/ \{2,\}//g' | tr -d '"' |
    sed "s|:/|_|g" | sort -u | xargs |
    sort -u | tr ' ' ',' | tr ':' '_'))
done

# If ${#cpes[@]} is empty we should bail
if [ ${#cpes[@]} -eq 0 ]; then
  echo "Error: Unable to locate any CPE data from report(s)."
  exit 1
fi


###############################################
# Normailze our CPE's to efficiently query vuldb
###############################################

# Break up existing CPE data in order to flatten it
for cpe in ${cpes[@]}; do
  tmp_vals+=($(echo "${cpe}" |
    awk -F, '{for(i=2;i<=NF;i++){printf("%s:%s\n", $1, $i)}}' | tr ',' ' '))
done

# Eliminate duplicate CPE data to maximize queries with VulDB
cpes=($(echo "${tmp_vals[@]}" | tr ' ' '\n' | sort -u))

# Be loud?
[ ${verbose} -eq 1 ] &&
  echo "Info: Found ${#cpes[@]} CPE(s) to search for possible CVE data"

# Create a filter for our cpe(s)
cpe_filter="$(echo "${cpes[@]}" | tr ' ' '\n' |
  cut -d: -f2 | tr '\n' '|')"


###############################################
# Search VulDB for possible CVE data matching our CPE
###############################################

# Get cached copies of VulDB reports
vuldb_reports=($(find ${reports_path} -type f -name "vuldb-*" 2>/dev/null |
  sort -n))

# Whittle down our available reports based on our targets
vuldb_reports=($(echo ${vuldb_reports[@]} |
  tr ' ' '\n' | egrep "${cpe_filter//:/_}"))

# Iterate our CPE's
for cpe in ${cpes[@]}; do

  # Split up our ${cpe} chunk
  ip="$(echo "${cpe}" | cut -d: -f1)"
  cpe="$(echo "${cpe}" | cut -d: -f2)"

  # Build a temporary array of possible reports matching our target
  reports_tmp=($(echo "${vuldb_reports[@]}" |
    tr ' ' '\n' | grep ${cpe//\//+}))

  # Does a cached report exist for ${target}
  if [ ${#reports_tmp[@]} -gt 0 ]; then

    # Use the latest report for cached time comparison
    report="$(echo "${reports_tmp[@]}" |
      tr ' ' '\n' | sort -n | tail -1)"

    # Get the Julian Day of year from the filename
    report_ts=$(echo "${report}" | cut -d"-" -f3)

    # Skip if ${report} is <= ${cached_time}
    if [ $(compare_jdoy_dates ${julian_datestamp} ${report_ts} ${cached_time}) -eq 0 ]; then

      # Be loud?
      [ ${verbose} -eq 1 ] &&
        echo "Info: Found cached vuldb data for ${cpe//_/:}..."

      # Add ${report} to our completed reports array
      vuldb_completed+=("${ip}:${report}")
      continue
    fi
  fi

  # Generate a new data payload for our request
  data="apikey=${vuldb_api_key}&search=${cpe//_/:},details=1"

  # Be loud?
  [ ${verbose} -eq 1 ] &&
    echo "Info: Searching for ${cpe//_/:} from ${vuldb_uri}"

  # Make the request
  curl -s -k --data "${data}" ${vuldb_uri} >> ${reports_path}/vuldb-${cpe//\//+}-${ts}

  # Add the new report to our conpleted array
  vuldb_completed+=("${ip}:${reports_path}/vuldb-${cpe//\//+}-${ts}")
done

# Handle duplicate reports
vuldb_completed=($(echo "${vuldb_completed[@]}" | tr ' ' '\n' | sort -u))

# Be loud?
[ ${verbose} -eq 1 ] &&
  echo "Info: Using ${#vuldb_completed[@]} report(s) to locate possible CVE data"


###############################################
# Use our VulDB report(s) to find CVE's applicable
###############################################

# Iterate ${vuldb_completed[@]}
for report in ${vuldb_completed[@]}; do

  # Get our target from the report name
  ip="$(echo "${report}" | cut -d: -f1)"
  report="$(echo "${report}" | cut -d: -f2)"

  # Strip out any potential CVE data
  tmp_cves=($(cat ${report} |
    jq '.result[]|.source.cve.id' 2>/dev/null | awk '$0 ~ /CVE/' | tr -d '"' | sort -u))

  # Include our ${ip} in the target CVE's
  cves+=("${ip}:$(echo "${tmp_cves[@]}" | tr ' ' ',')")

  # Calc a total found
  total_cves=$(expr ${total_cves:=0} + ${#tmp_cves[@]})
done

# If we don't have any CVE's bail
if [ ${total_cves} -eq 0 ]; then
  echo "Error: Unable to locate any CVE(s) from report(s) about target(s)."
  exit 1
fi

# Be loud?
[ ${verbose} -eq 1 ] &&
  echo "Info: Found ${total_cves} CVE(s) applicable to ${targets[@]//_/:}"


###############################################
# Test our assets and create if necessary
###############################################

# Get an array of CVE assets
assets=($(find ${assets_path} -type f 2>/dev/null | sort -n))

# If we don't have any attempt to get one
if [ ${#assets[@]} -eq 0 ]; then

  # Be loud?
  [ ${verbose} -eq 1 ] &&
    echo "Warning: No CVE datasources found. Downloading..."

  # Timestamp new CVE datasource asset
  curl -s ${cve_assets_location} > ${assets_path}/${ts}

  # Set the CVE asset name
  cve_asset="${assets_path}/${ts}"
else

  # Get the last entry in ${assets[@]} as our CVE datasource
  cve_asset="$(echo "${assets[@]}" | tr ' ' '\n' | sort -n | tail -1)"

  # Get the Julian Day of year from the filename
  cve_asset_ts=$(echo "${cve_asset}" | cut -d"-" -f2)

  # Is the ${cve_asset} older than threshold defined in ${cached_time}?
  if [ $(compare_jdoy_dates ${julian_datestamp} ${cve_asset_ts} ${cached_time}) -gt 0 ]; then

    # Timestamp new CVE datasource asset
    curl -s ${cve_assets_location} > ${assets_path}/${ts}

    # Set the CVE asset name
    cve_asset="${assets_path}/${ts}"
  fi
fi

# Be loud?
[ ${verbose} -eq 1 ] &&
  echo "Info: Using ${cve_asset} as CVE datasource"


###############################################
# Search for exploits applicable to our found CVE's
###############################################

# Iterate our CVE's
for cve in ${cves[@]}; do

  # Get our IP first
  ip="$(echo "${cve}" | cut -d: -f1)"

  # Create an filter from our CVE's
  filter="$(echo "${cve}" | cut -d: -f2 | tr ',' '|')"

  # Bail if ${filter} is null
  [ "${filter}" = "" ] &&
    continue

  # Search for exploits from ${cve_asset} using our CVE ${filter}
  exploits=($(zegrep -i ${filter} ${cve_asset} | grep "EXPLOIT-DB:" |
    sed -n 's/.*EXPLOIT-DB:\(.* \) .*|.*/\1/p' |
    awk '{print $1}' | sort -u |
    xargs -iS printf "https://www.exploit-db.com/explits/%s\n" S))


  # Skip if nothing found for host
  [ ${#exploits[@]} -eq 0 ] &&
    continue

  # Be loud?
  [ ${verbose} -eq 1 ] &&
    echo "Info: Found ${#exploits[@]} exploit(s) for ${ip}..."

  # Inform the user
  cat <<_eof_
Target: ${ip//_/:}
CVE(s): ${filter//|/,}
Exploit(s): ${exploits[@]}

_eof_
done
