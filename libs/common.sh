#!/bin/bash

# @description Provides help menu
#
# @stdout Text blob
function usage()
{

  cat <<EOF
recon.sh - Research targets

Usage ./recon.sh [options]

 Options:
    -c  Cached time for CVE datasource
    -r  Use existing report
    -t  Targets; supports files, CSV or colon separated lists
    -v  Enable verbosity

EOF
}


# @description Determine list of targets
#
# @arg ${@} Array of args
#
# @stdout Array
function determine_targets()
{
  local targets=("${@}")

  # If ${targets[@]} is still empty use locally configured networks
  #   Supports RHEL<>7 toolsets & filters for loopbacks & non-routeables
  [ -z "${targets}" ] &&
    targets=($((ifconfig -a 2>/dev/null;ip addr 2>/dev/null) |
      awk '$1 ~ /inet/ && $2 !~ /^127|^::|^192/{print $2}' |
      cut -d"/" -f1 | sort -u))

  # Handle files as our target source
  [[ ! -z "${targets}" ]] && [[ -f ${targets} ]] &&
    targets=($(cat ${targets} | sort -u))


  # Is ${targets} a CSV or colon separated data type?
  [[ ! -z "${targets}" ]] && [[ $(echo ${targets} | egrep -c ',|:') -gt 0 ]] &&
    targets=($(targets} | tr ',' ' ' | tr ':' ' ' | sort -u))

  # Last ditch effort, use ifconfig.me
  [ ${#targets[@]} -eq 0 ] &&
    targets=($(curl -s https://ifconfig.me/ip))

  # Now we need to convert any possible hostnames to IP addresses
  for target in ${targets[@]}; do
    if [ $(echo "${target}" | grep -c "^[0-9]") -gt 0 ]; then
      tmp_targets+=("${target}")
    else
      tmp_targets+=($(nslookup ${target} 2>/dev/null |
        awk '$1 ~ /Name:/{getline;print $NF}' | tr ':' '_'))
    fi
  done

  # Replace original array
  targets=(${tmp_targets[@]})

  # Return
  echo "${targets[@]}"
}


# @description Acquire/Use shodan report
#
# @arg ${@} Array of args
#
# @stdout Array
function set_shodan_reports()
{
set -x
  local args=("${@}")
  local reports_path="${args[0]}"
  local -a targets=(${args[@]:1})
  local report
  local report_ts
  local -a reports
  local -a reports_tmp
  local -a shodan_completed

  # Get an array of reports
  if [ ${#reports[@]} -eq 0 ]; then
    reports=($(find .${reports_path} -type f -name "shodan-*" 2>/dev/null | sort -n))

    # Iterate our targets
    for target in ${targets[@]}; do

      # Build a temporary array of possible reports matching our target
      reports_tmp=($(echo "${reports[@]}" |
        tr ' ' '\n' | grep ${target//\./\\.}))

      # Does a cached report exist for ${target}
      if [ ${#reports_tmp[@]} -gt 0 ]; then

        # Use the latest report for cached time comparison
        report="$(echo "${reports_tmp[@]}" |
          tr ' ' '\n' | sort -n | tail -1)"

        # Get the Julian Day of year from the filename
        report_ts=$(echo "${report}" | cut -d"-" -f2)

        # Skip if ${report} is <= ${cached_time}
        if [ $(compare_jdoy_dates ${julian_datestamp} ${report_ts} ${cached_time}) -eq 1 ]; then

          # Add ${report} to our completed reports array
          completed+=("${report}")
          continue
        fi
      fi

      # Execute scan request
      curl -s -X GET "${shodan_uri}/${target}?key=${shodan_api_key}" > ${reports_path}/shodan-${target}-${ts}

      # Keep track of what our completed reports
      shodan_completed+=("${reports_path}/shodan-${target}-${ts}")
    done
  else

    # Set our report to the user provided
    shodan_completed=${reports[@]}
  fi

  echo "${shodan_completed[@]}"
}
