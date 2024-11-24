#脆弱性検知
DAY=`date +%Y%m%d%H%M`

BRANCH_NAME=`echo $GIT_BRANCH | cut -d '/' -f 2`
REPOSITORY_NAME='Jenkins_pipeline_test'

#sbomディレクトリを作成し、現在のタグに対してsbom_${TAG_NAME}.jsonを生成
#sbomディレクトリ
SBOM_DIR=sbom/
SBOM_DIR_CURRE=sbom_curre/
SBOM_DIR_PAST=sbom_past/
SBOM_FILE="sbom_${REPOSITORY_NAME}_${BRANCH_NAME}"
SBOM_DIFF_DIR=sbom_diff/


#日付処理
#cp ${VULN_DIR}${VULN_DIR_CURRE}${GRYPE_FILE}.txt ${VULN_DIR}${VULN_DIR_PAST}${GRYPE_FILE}_${DAY}.txt
cp ${SBOM_DIR}${SBOM_DIR_CURRE}${SBOM_FILE}.json ${SBOM_DIR}${SBOM_DIR_PAST}${SBOM_FILE}_${DAY}.json


#grype sbom:./${SBOM_DIR}${SBOM_DIR_CURRE}${SBOM_FILE}.json --only-fixed -o table=${VULN_DIR}${VULN_DIR_CURRE}${GRYPE_FILE}_fixed.txt
#grype sbom:./${SBOM_DIR}${SBOM_DIR_CURRE}${SBOM_FILE}.json --only-notfixed -o table=${VULN_DIR}${VULN_DIR_CURRE}${GRYPE_FILE}_notfixed.txt

VULN_DIR="vuln/"
GRYPE_FILE="vuln_table_${REPOSITORY_NAME}_${BRANCH_NAME}"
VULN_DIR_CURRE="vuln_curre/"
VULN_DIR_PAST="vuln_past/"
if [ ! -d ${VULN_DIR} ]; then
  mkdir -p ${VULN_DIR}${VULN_DIR_CURRE}
  mkdir -p ${VULN_DIR}${VULN_DIR_PAST}
fi


#grypeで最新developブランチのSBOMをスキャンする
grype_vuln_scan() {
  local _sbom_target=$1
  local _results_file=$2
  #grype db status
  #export GRYPE_DB_AUTO_UPDATE=false
  #export GRYPE_CHECK_FOR_APP_UPDATE=false
  grype sbom:./"${_sbom_target}" -o table="${_results_file}".txt
  grype sbom:./"${_sbom_target}" -o json="${_results_file}".json
}

detect_high_critical_vulnerabilities_fixed() {

    local _fixed_state="$1"

    cd "${_fixed_state}"
    grep -E 'AV:N|AV:A' vuln_"${_fixed_state}"_tmp.csv | grep -E 'High|Critical' > vuln_"${_fixed_state}".csv || true
    # 直前のコマンドの終了コードを取得
    exit_code=$?
    echo ${exit_code}
    # 終了コードが0以外（エラーが発生した）場合はスキップする
    if [ $exit_code -ne 0 ]; then
        echo "${_fixed_state}" ": High or Critical are not found. Skipping the execution of the shell script."
        #exit $exit_code
    else
        #cp vulntmp.csv vulntmp1.csv
        rm vuln_"${_fixed_state}"_tmp.csv
        awk -F '","' '!seen[$1 $3]++' vuln_"${_fixed_state}".csv > vuln_"${_fixed_state}"_tmp.csv
        #sed -i '1s/^/Package name,version, purl, fixed-in, VULNERABILITY, SEVERITY, CVSS1, CVSS2, CVSS3, CVSS4\n/' vulntmp.csv
        
        awk -F '","' '{printf("| %-15s | %-12s | %-13s | %-12s | %s |\n", $1, $2, $3, $4, $5)}' vuln_"${_fixed_state}"_tmp.csv > marktable_"${_fixed_state}".txt
        sed -i '1s/^/|パッケージ名|バージョン|修正バージョン|VULNERABILITY|SEVERITY|\n/' marktable_"${_fixed_state}".txt
        sed -i '2 i\|-----------------|--------------|--------------|----------------------|----------|' marktable_"${_fixed_state}".txt
        sed 's/^\|"//g; s/"$//g' marktable_"${_fixed_state}".txt > marktable_"${_fixed_state}"0.txt
        VULNERABILITY_DATA=\`\`\`$(cat marktable_"${_fixed_state}"0.txt)\`\`\`
        rm marktable_"${_fixed_state}".txt marktable_"${_fixed_state}"0.txt
    fi
    cd ..
}

detect_high_critical_vulnerabilities_other() {

    local _fixed_state="$1"

    cd "${_fixed_state}"
    grep -E 'AV:N|AV:A' vuln_"${_fixed_state}"_tmp.csv | grep -E 'High|Critical' > vuln_"${_fixed_state}".csv || true
    # 直前のコマンドの終了コードを取得
    exit_code=$?
    echo ${exit_code}
    # 終了コードが0以外（エラーが発生した）場合はスキップする
    if [ $exit_code -ne 0 ]; then
        echo "${_fixed_state}" ": High or Critical are not found. Skipping the execution of the shell script."
        #exit $exit_code
    else
        #cp vulntmp.csv vulntmp1.csv
        rm vuln_"${_fixed_state}"_tmp.csv
        awk -F '","' '!seen[$1 $3]++' vuln_"${_fixed_state}".csv > vuln_"${_fixed_state}"_tmp.csv
        #sed -i '1s/^/Package name,version, purl, fixed-in, VULNERABILITY, SEVERITY, CVSS1, CVSS2, CVSS3, CVSS4\n/' vulntmp.csv
        
        awk -F '","' '{printf("| %-15s | %-12s | %-13s | %-12s |\n", $1, $2, $3, $4)}' vuln_"${_fixed_state}"_tmp.csv > marktable_"${_fixed_state}".txt
        sed -i '1s/^/|パッケージ名|バージョン|VULNERABILITY|SEVERITY|\n/' marktable_"${_fixed_state}".txt
        sed -i '2 i\|-----------------|--------------|--------------|----------|' marktable_"${_fixed_state}".txt
        sed 's/^\|"//g; s/"$//g' marktable_"${_fixed_state}".txt > marktable_"${_fixed_state}"0.txt
        VULNERABILITY_DATA=\`\`\`$(cat marktable_"${_fixed_state}"0.txt)\`\`\`
        rm marktable_"${_fixed_state}".txt marktable_"${_fixed_state}"0.txt
    fi
    cd ..
}

echo "---> grype vulnerability-scan"
grype_vuln_scan ${SBOM_DIR}${SBOM_DIR_CURRE}${SBOM_FILE}.json ${VULN_DIR}${VULN_DIR_CURRE}${GRYPE_FILE}

CRITICAL_NUM=`grep -o "Critical" ${VULN_DIR}${VULN_DIR_CURRE}${GRYPE_FILE}.txt | wc -l`
HIGH_NUM=`grep -o "High" ${VULN_DIR}${VULN_DIR_CURRE}${GRYPE_FILE}.txt | wc -l`

DIRECTORY_NAME=${GRYPE_FILE}/

if [ ! -d "${DIRECTORY_NAME}" ]; then
    mkdir -p ${DIRECTORY_NAME}
fi

if [ -e "${VULN_DIR}${VULN_DIR_CURRE}${GRYPE_FILE}.json" ]; then
	cp ${VULN_DIR}${VULN_DIR_CURRE}${GRYPE_FILE}.txt ${DIRECTORY_NAME}
    cp ${VULN_DIR}${VULN_DIR_CURRE}${GRYPE_FILE}.json ${DIRECTORY_NAME}
    cp ${VULN_DIR}${VULN_DIR_CURRE}${GRYPE_FILE}.txt ${VULN_DIR}${VULN_DIR_PAST}${GRYPE_FILE}_${DAY}.txt
    cp ${VULN_DIR}${VULN_DIR_CURRE}${GRYPE_FILE}.json ${VULN_DIR}${VULN_DIR_PAST}${GRYPE_FILE}_${DAY}.json
fi

cd $DIRECTORY_NAME

# make fixed directory to store fixed vulnerabilities.
if [ ! -d "fixed" ]; then
    mkdir -p fixed
fi
# FIXED
if cat ${GRYPE_FILE}.json | jq -r '.matches[] | .vulnerability.fix.state | contains("fixed")'  | grep true >/dev/null; then
    cat ${GRYPE_FILE}.json | jq -r '
    .matches[] 
    | select(.vulnerability.fix.state == "fixed") 
    | [
        .artifact.name,
        .artifact.version,
        .vulnerability.fix.versions[],
        if (.vulnerability.id | contains("CVE-")) and (.vulnerability.cvss = null) and (.relatedVulnerabilities[0].id as $CVE | .vulnerability.id == $CVE)
        then
            .vulnerability.id,
            .vulnerability.severity,
            (.relatedVulnerabilities[0].cvss | last | .version),
            (.relatedVulnerabilities[0].cvss | last | .vector)
        elif (.vulnerability.id | contains("CVE-")) and (.vulnerability.cvss != null)
        then
            .vulnerability.id,
            .vulnerability.severity,
            (.vulnerability.cvss | last |.version),
            (.vulnerability.cvss | last |.vector)
        else
            .relatedVulnerabilities[0].id,
            .relatedVulnerabilities[0].severity,
            (.relatedVulnerabilities[0].cvss | last | .version),
            (.relatedVulnerabilities[0].cvss | last | .vector)
        end
    ] | @csv' > fixed/vuln_fixed_tmp.csv

    detect_high_critical_vulnerabilities_fixed fixed
    VULNERABILITY_DATA_FIXED=${VULNERABILITY_DATA}
else
    # .vulnerability.fix.stateが"fixed"を含まない場合、メッセージを表示
    echo "The 'fixed' string is not found. Skipping the execution of the shell script."
fi

#NON-FIXED
if [ ! -d "not-fixed" ]; then
    mkdir -p not-fixed
fi

if cat ${GRYPE_FILE}.json | jq -r '.matches[] | .vulnerability.fix.state | contains("not-fixed")' | grep true >/dev/null; then
    cat ${GRYPE_FILE}.json | jq -r '
    .matches[] 
    | select(.vulnerability.fix.state == "not-fixed") 
    | [
        .artifact.name,
        .artifact.version,
        if (.vulnerability.id | contains("CVE-")) and (.vulnerability.cvss = null) and (.relatedVulnerabilities[0].id as $CVE | .vulnerability.id == $CVE)
        then
            .vulnerability.id,
            .vulnerability.severity,
            (.relatedVulnerabilities[0].cvss | last | .version),
            (.relatedVulnerabilities[0].cvss | last | .vector)
        elif (.vulnerability.id | contains("CVE-")) and (.vulnerability.cvss != null)
        then
            .vulnerability.id,
            .vulnerability.severity,
            (.vulnerability.cvss | last |.version),
            (.vulnerability.cvss | last |.vector)
        else
            .relatedVulnerabilities[0].id,
            .relatedVulnerabilities[0].severity,
            (.relatedVulnerabilities[0].cvss | last | .version),
            (.relatedVulnerabilities[0].cvss | last | .vector)
        end
    ] | @csv' > not-fixed/vuln_not-fixed_tmp.csv
    
    detect_high_critical_vulnerabilities_other not-fixed
    VULNERABILITY_DATA_NOTFIXED=${VULNERABILITY_DATA}

else
    # .vulnerability.fix.stateが"not-fixed"を含まない場合、メッセージを表示
    echo "The 'not-fixed' string is not found. Skipping the execution of the shell script."
fi

# UNKNOWN
if [ ! -d "unknown" ]; then
    mkdir -p unknown
fi
if cat ${GRYPE_FILE}.json | jq -r '.matches[] | .vulnerability.fix.state | contains("unknown") // contains("wont-fix")' | grep true  >/dev/null; then
    cat ${GRYPE_FILE}.json | jq -r '
    .matches[] 
    | select(.vulnerability.fix.state == "unknown" or .vulnerability.fix.state == "wont-fix") 
    | [
        .artifact.name,
        .artifact.version,
        if (.vulnerability.id | contains("CVE-")) and (.vulnerability.cvss = null) and (.relatedVulnerabilities[0].id as $CVE | .vulnerability.id == $CVE)
        then
            .vulnerability.id,
            .vulnerability.severity,
            (.relatedVulnerabilities[0].cvss | last | .version),
            (.relatedVulnerabilities[0].cvss | last | .vector)
        elif (.vulnerability.id | contains("CVE-")) and (.vulnerability.cvss != null)
        then
            .vulnerability.id,
            .vulnerability.severity,
            (.vulnerability.cvss | last |.version),
            (.vulnerability.cvss | last |.vector)
        else
            .relatedVulnerabilities[0].id,
            .relatedVulnerabilities[0].severity,
            (.relatedVulnerabilities[0].cvss | last | .version),
            (.relatedVulnerabilities[0].cvss | last | .vector)
        end
    ] | @csv' > unknown/vuln_unknown_tmp.csv
        
    detect_high_critical_vulnerabilities_other unknown
    VULNERABILITY_DATA_UNKOWN=${VULNERABILITY_DATA}
else
    # .vulnerability.fix.stateが"unknown"を含まない場合、メッセージを表示
    echo "The 'unknown' string is not found. Skipping the execution of the shell script."
fi

cd ..

LIB=`awk 'BEGIN {
  # テーブルヘッダーを出力
  print "| NAME | INSTALLED-VERSION |"
  print "|------|-----------|"
}
NR>1 {
  # NAME と INSTALLED 列だけを出力
  printf("| %s | %s |\n", $1, $2)
}' ${VULN_DIR}${VULN_DIR_CURRE}${GRYPE_FILE}.txt | uniq`

JSON_INFO=`cat << EOF
{
    "text": "レベルHigh, Criticalの脆弱性が見つかりました。",
    "blocks": [
    	{
    		"type": "section",
    		"text": {
    			"type": "mrkdwn",
    			"text": "レベルHigh, Criticalの脆弱性が見つかりました。:"
    		}
    	},
    	{
    		"type": "section",
    		"block_id": "section789",
    		"fields": [
    			{
    				"type": "mrkdwn",
    				"text": "*日付*: ${DAY}"
    			},
                {
    				"type": "mrkdwn",
    				"text": "*branch*: ${BRANCH_NAME}"
    			},
                {
    				"type": "mrkdwn",
    				"text": "*JOB name*: ${JOB_NAME} #${BUILD_ID}"
    			},
                {
    				"type": "mrkdwn",
    				"text": "*JOBのURL*: ${BUILD_URL}"
    			},
                {
    				"type": "mrkdwn",
    				"text": "*CRITICALの件数*: ${CRITICAL_NUM}"
    			},
                {
    				"type": "mrkdwn",
    				"text": "*HIGHの件数*: ${HIGH_NUM}"
    			},
    		]
    	},
        {
        	"type": "section",
    		"text": {
    			"type": "mrkdwn",
    			"text": "FIXED-INに記されたバージョンへアップデートをお願いします"
    		}
		},
        {
        	"type": "section",
    		"text": {
    			"type": "mrkdwn",
    			"text": "${VULNERABILITY_DATA_FIXED}"
    		}
		},
        {
        	"type": "section",
    		"text": {
    			"type": "mrkdwn",
    			"text": "次の脆弱性については、修正バージョンが公開されていません。"
    		}
		},
        {
        	"type": "section",
    		"text": {
    			"type": "mrkdwn",
    			"text": "${VULNERABILITY_DATA_NOTFIXED}"
    		}
		},
        {
        	"type": "section",
    		"text": {
    			"type": "mrkdwn",
    			"text": "次の脆弱性については、脆弱性対策が知られていません。"
    		},
		},
        {
        	"type": "section",
    		"text": {
    			"type": "mrkdwn",
    			"text": "${VULNERABILITY_DATA_UNKOWN}"
    		}
    	}
    ]
}
EOF`

#プロキシを設定する場合は、プロキシを環境変数で設定
#export HTTP_PROXY=
#export HTTPS_PROXY=

#Web hook用URLの設定
WEBHOOK_URL=https://hooks.slack.com/services/

if grep -q "Critical" ${DIRECTORY_NAME}${GRYPE_FILE}.json || grep -q "High" ${DIRECTORY_NAME}${GRYPE_FILE}.json; then
  echo "alerm"

  curl -X POST -H 'Content-type: application/json' -d "${JSON_INFO}" "${WEBHOOK_URL}"    
  #curl -H "Content-Type: application/json" -d "${JSON_INFO}" "${WEBHOOK_URL}"
fi