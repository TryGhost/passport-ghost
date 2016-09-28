module.exports = function(grunt) {
    // Project configuration.
    grunt.initConfig({
        release: {
            github: {
                repo: 'TryGhost/passport-ghost',
                accessTokenVar: 'GITHUB_ACCESS_TOKEN'
            }
        }
    });

    grunt.loadNpmTasks('grunt-release');
};
