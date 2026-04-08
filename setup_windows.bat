@echo off
echo Instalando dependencias para Windows...
python -m venv venv
call venv\Scripts\activate
pip install flask==3.0.3 flask-limiter==3.7.0 requests==2.32.3
echo.
echo ✅ Instalacao concluida!
echo.
echo Para rodar o sistema digite:
echo   venv\Scripts\activate
echo   python app.py
echo.
echo Depois abra: http://localhost:5000
pause
