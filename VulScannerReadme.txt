To get back to the application and start it up after restarting Windows, follow these simple steps:

Start Docker Desktop: Once your computer reboots, ensure Docker Desktop is running. You can open it from the Start Menu. Wait for the Docker icon in your system tray to show that the Docker engine is running.
Open a Terminal: Open PowerShell or Command Prompt.
Navigate to the Project Directory: Run the following command to go to your application's folder:
bash


cd "d:\AntiGravity Projects\Vulnerability Scanner"
Start the Application: Run the Docker Compose command to build the containers and start everything in the background:
bash


docker compose up -d --build
(Note: You can omit --build on future runs if you haven't changed any code. Just docker compose up -d will instantly turn the app back on.)
Once the command finishes, the application will be running! You can access it in your web browser:

Frontend User Interface: http://localhost:5173
Backend API Documentation: http://localhost:8000/docs
If you need to stop the application later, you can simply run "docker compose down" in that same folder.