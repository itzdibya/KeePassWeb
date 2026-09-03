module.exports = {
  apps: [
    {
      name: 'pdf-editor',
      script: '/usr/bin/serve',
      args: '-s /home/sysadmin/pdf-suite -l tcp://0.0.0.0:3000',
      cwd: '/home/sysadmin/pdf-suite',
      instances: 1,
      autorestart: true,
      watch: false
    },
    {
      name: 'keepass2',
      script: 'server.js',
      cwd: '/home/sysadmin/keepass2',
      instances: 1,
      autorestart: true,
      watch: false,
      max_memory_restart: '500M',
      env: {
        NODE_ENV: 'production',
        PORT: 3080,
        HOST: '0.0.0.0'
      }
    }
  ]
};
