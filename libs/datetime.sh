#!/bin/bash


# @description Convert current/supplied date to Julian Day of Year
#
# @arg ${1} Day
# @arg ${2} Month
# @arg ${3} Year
#
# @example
#   conv_date_jdoy
#   conv_date_jdoy 27 6 1975
#
# @stdout Integer
function conv_date_to_jdoy()
{
  local dte="$(date +%d:%m:%Y)"

  local tday=$(echo "${dte}" | cut -d: -f1)
  local tmon=$(echo "${dte}" | cut -d: -f2)
  local tyear=$(echo "${dte}" | cut -d: -f3)

  local day="$([ ! -z ${1} ] && echo "${1}" || echo "${tday}")"
  local mon="$([ ! -z ${2} ] && echo "${2}" || echo "${tmon}")"
  local year="$([ ! -z ${3} ] && echo "${3}" || echo "${tyear}")"
  local sum

  if [ ${mon} -le 2 ]; then
    year=$(( ${year} - 1 ))
    mon=$(( ${mon} + 12 ))
  else
    year=${year}
    mon=${mon}
  fi

  sum=$(echo  "2 - ${year} / 100 + ${year} / 400" | bc)
  sum=$(echo  "(${sum} + 365.25 * (${year} + 4716)) / 1" | bc)
  sum=$(echo "(${sum} + 30.6001 * (${mon} + 1)) / 1" | bc)

  echo $(echo "${sum} + ${day} - 1524.5" | bc) | cut -d"." -f1
}


# @description Compare two Julian Dates
#
# @arg ${1} Current
# @arg ${2} Compariative
# @arg ${3} Minimum integer
#
# @example
#   compare_jdoy_dates 2458461.5 2442590.5 30
#   compare_jdoy_dates $(conv_date_to_jdoy) $(conv_date_to_jody 27 6 27) 56
#
# @stdout Integer true/false
function compare_jdoy_dates()
{
  local current="${1}"
  local compare="${2}"
  local min="${3}"
  local result=$(echo "${current} - ${compare}" | bc | cut -d. -f1)

  [ ${result} -ge ${min} ] &&
    echo 1 || echo 0
}
