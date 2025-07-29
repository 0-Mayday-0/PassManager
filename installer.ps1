New-Item -Path . -ItemType Directory -Name "crypto"
New-Item -Path .\crypto -ItemType File -Name ".env"
New-Item -Path .\crypto -ItemType File -Name "passdb.json"

winget install "Python 3.13" --source winget

$env:PATH = $env:PATH + "C:\Users\User\AppData\Local\Programs\Python\Python313;" +
                        "C:\Users\User\AppData\Local\Programs\Python\Python313\Scripts;"

pip install -r requirements.txt
pip install pyclip
pip install pyinstaller

python ".\keys.py"

pyinstaller manage.py --onefile

Move-Item -Path .\dist\manage.exe -Destination .
rm .\dist -Recurse -Force
rm .\build -Recurse -Force
rm .\manage.spec -Force