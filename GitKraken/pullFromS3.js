const fs = require("fs");
const fse = require("fs-extra");
const path = require("path");
const got = require("got");
const stream = require("stream")
const util = require("util");

const pipeline = util.promisify(stream.pipeline);

const { gitkrakenPrebuilts: { bucketName } } = require('./package.json');
const { version } = require("../package.json");
const rebuildConfig = require("./rebuild_docker_config.json");
const { getDistNames } = require("./configHelper");

const binaryDir = path.resolve(__dirname, "additional-binaries");
const buildReleaseDir = path.resolve(__dirname, "..", "build", "Release");

const getBinaryName = (distName, version) => `nodegit-${version}-${distName}.node`;
const getFriendlyBinaryName = distName => `nodegit-${distName}.node`;

const downloadBinaryFromS3 = async binaryName => {
  await pipeline(
    got.stream(`https://${bucketName}.s3.amazonaws.com/${binaryName}`),
    fs.createWriteStream(path.resolve(binaryDir, binaryName))
  )
};

const downloadAllBinaries = async () => {
  const distNames = getDistNames(rebuildConfig);
  for (const distName of distNames) {
    const binaryName = getBinaryName(distName, version);
    await downloadBinaryFromS3(binaryName);
  }
};

const copyBinaries = async () => {
  const distNames = getDistNames(rebuildConfig);
  for (const distName of distNames) {
    const binaryName = getBinaryName(distName, version);
    const friendlyBinaryName = getFriendlyBinaryName(distName);

    await fse.copy(
      path.resolve(binaryDir, binaryName),
      path.resolve(buildReleaseDir, friendlyBinaryName)
    );
  }
};

const cleanup = async () => {
  await fse.remove(binaryDir);
  await fse.remove(path.join(__dirname, 'node_modules'));
};

const acquireBinariesFromS3 = async () => {
  await fse.ensureDir(binaryDir);
  await downloadAllBinaries();
  await copyBinaries();
  await cleanup();
};

module.exports = acquireBinariesFromS3;

if (require.main === module) {
  module.exports().catch((error) => {
    console.error('Pull from S3 failed: ', error);
    process.exit(1);
  });
}
