#現在のタグとその前のタグの環境変数を定義
#VERSION_TAG_LIST=`git tag -l 'v*'` || true
#TAG_HASH=`git rev-list ${VERSION_TAG_LIST} --max-count=1` || true
#TAG_NAME=`git describe --abbrev=0 --tags ${TAG_HASH}` || true
#PRE_TAG_HASH=`git rev-list ${VERSION_TAG_LIST} --skip=1 --max-count=1` || true
#PRE_TAG_NAME=`git describe --abbrev=0 --tags ${PRE_TAG_HASH}` || true
#echo $TAG_NAME || true
#echo $PRE_TAG_NAME || true

BRANCH_NAME=`echo $GIT_BRANCH | cut -d '/' -f 2`
REPOSITORY_NAME='Jenkins_pipeline_test'


#sbomディレクトリを作成し、最新ブランチに対してsbom_${BRANCH_NAME}.jsonを生成
SBOM_DIR=sbom/
SBOM_DIR_CURRE=sbom_curre/
SBOM_DIR_PAST=sbom_past/
SBOM_FILE="sbom_${REPOSITORY_NAME}_${BRANCH_NAME}"
SBOM_LIST_DIR=sbom_list/
SBOM_LIST_DIR_CURRE=sbom_list_curre/
SBOM_LIST_DIR_PAST=sbom_list_past/
SBOM_FILE_ARRANGED="sbom_list_${REPOSITORY_NAME}_${BRANCH_NAME}"
#ディレクトリを作る
if [ ! -d ${SBOM_DIR} ]; then
  mkdir -p ${SBOM_DIR}${SBOM_DIR_CURRE}
  mkdir -p ${SBOM_DIR}${SBOM_DIR_PAST}
fi
if [ ! -d ${SBOM_LIST_DIR} ]; then
  mkdir -p ${SBOM_LIST_DIR}${SBOM_LIST_DIR_CURRE}
  mkdir -p ${SBOM_LIST_DIR}${SBOM_LIST_DIR_PAST}
fi
if [ ! -d ${SBOM_LIST_DIR}${SBOM_LIST_DIR_CURRE}${SBOM_FILE_ARRANGED} ]; then
  mkdir -p ${SBOM_LIST_DIR}${SBOM_LIST_DIR_CURRE}${SBOM_FILE_ARRANGED}
fi
#vulnディレクトリを作成し、現在のタグに対してvuln_table_${BRANCH_NAME}.txtを生成
VULN_DIR="vuln/"
GRYPE_FILE="vuln_table_${REPOSITORY_NAME}_${BRANCH_NAME}"
VULN_DIR_CURRE="vuln_curre/"
VULN_DIR_PAST="vuln_past/"
if [ ! -d ${VULN_DIR} ]; then
  mkdir -p ${VULN_DIR}${VULN_DIR_CURRE}
  mkdir -p ${VULN_DIR}${VULN_DIR_PAST}
fi

#Docker build
imageName=poetry
imageTag="sbom"_$BUILD_ID
TARGET=$imageName:$imageTag

docker build -t ${TARGET} .


#syftでSBOMを生成する
sbom_create() {
  local _target=$1
  local _sbom_curre_file=$2
  local _sbom_past_file=$3
  syft --version
  if [ -e  "${_sbom_curre_file}" ]; then
    cp "${_sbom_curre_file}"  "${_sbom_past_file}"
  fi
  syft image:"${_target}" -o cyclonedx-json="${_sbom_curre_file}"
}
echo "---> start syft scan"
sbom_create ${TARGET} ${SBOM_DIR}${SBOM_DIR_CURRE}${SBOM_FILE}.json ${SBOM_DIR}${SBOM_DIR_PAST}${SBOM_FILE}_prev.json

docker image rm ${TARGET}
