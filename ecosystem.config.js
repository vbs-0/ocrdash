// pm2 process manager config for the LensIQ management server.
//   pm2 start ecosystem.config.js
//   pm2 save && pm2 startup     (to survive reboots)
module.exports = {
  apps: [
    {
      name: "lensiq-backend",
      script: "mgmt_server.py",
      interpreter: "python3",
      cwd: __dirname,
      env: { LENSIQ_MGMT_PORT: "7788", LENSIQ_SECRET: "CHANGE-ME-to-a-long-random-string" },
      autorestart: true,
      max_restarts: 20,
    },
    {
      name: "lensiq-frontend",
      script: "frontend_server.py",
      interpreter: "python3",
      cwd: __dirname,
      env: { LENSIQ_FRONTEND_PORT: "7789" },
      autorestart: true,
      max_restarts: 20,
    },
  ],
};
