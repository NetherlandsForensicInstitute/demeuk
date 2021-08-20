from os import linesep, mkdir, path
from shutil import rmtree

if path.isdir('testdata'):
    rmtree('testdata')
mkdir('testdata')

with open('testdata/input1', 'wb') as file:
    # ascii
    file.write(f'Password123!@"{linesep}'.encode('utf-8'))
    # empty line
    file.write(f'{linesep}'.encode('utf-8'))
    # Some weird utf-8 chars
    file.write(f'ǓǝǪǼȧɠ{linesep}'.encode('utf-8'))
    file.write(f'ʄʛʨʾϑϡϣЄ{linesep}'.encode('utf-8'))
    # UTF-16
    file.write('ϽϾϿЀЁЂЃЄЅІЇЈ'.encode('utf-16') + f'{linesep}'.encode('utf-8'))
    # Chinese
    file.write(b'\xe5\x81\x9a\xe6\x88\x8f\xe4\xb9\x8b\xe8\xaf\xb4' + f'{linesep}'.encode('utf-8'))
    # Invalid chars
    file.write(b'\x01' + f'{linesep}'.encode('utf-8'))
    # ..i.??fcXyC
    file.write(b'\x01\x1f\x69\x05\x3f\x3f\x66\x63\x58\x79\x43' + f'{linesep}'.encode('utf-8'))
    # ..zyj4554
    file.write(b'\x0c\x7a\x79\x6a\x34\x35\x35\x34' + f'{linesep}'.encode('utf-8'))
    # Latin1
    file.write(f'Hyggelig123åmøtedeg!{linesep}'.encode('latin1'))
    # Left to right marker.
    file.write(b'\xe2\x80\x8f' + f'ϽϾϿЀЁЂЃЄЅІЇЈ{linesep}'.encode('utf-8'))
    # Russian
    file.write(f'бонусов$123{linesep}'.encode('ISO-8859-5'))
    file.write(f'!!!ееместной%%@!{linesep}'.encode('WINDOWS-1251'))

with open('testdata/input2', 'wb') as file:
    for x in range(8):
        file.write(f'line{x}{linesep}'.encode('utf-8'))

with open('testdata/input3', 'wb') as file:
    for x in range(8):
        file.write(f'line{x}'.encode('utf-8') + b'\x0d\x0a')

with open('testdata/input4', 'wb') as file:
    file.write('line'.encode('utf-8') + b'\x09' + f'entry{linesep}'.encode('utf-8'))
    file.write('line2'.encode('utf-8') + b'\x09\x09' + f'entry2{linesep}'.encode('utf-8'))

with open('testdata/input5', 'w') as file:
    file.write(f'line1{linesep}')
    file.write(f'line2{linesep}')
    file.write(f'line3{linesep}')
    file.write(f'email@example.com:line4{linesep}')
    file.write(f'email@example.com;line5{linesep}')
    file.write(f'test:email@example.com:line6{linesep}')

with open('testdata/input6', 'w') as file:
    file.write(f'I\'Afrique_ADJ occidental_ADJ\t1927\t2\t2{linesep}')
    file.write(f'I\'Allemagne )\t2009\t1\t1{linesep}')
    file.write(f'I\'ain _VERB_\t2009\t2\t2{linesep}')
    file.write(f'I\'ain a_VERB\t2009\t2\t2{linesep}')

with open('testdata/input7', 'wb') as file:
    # coupÉ
    file.write(b'\x63\x6F\x75\x70\xC3\x89' + f'{linesep}'.encode('utf-8'))
    # LANCIA AURELIA B20 COUPÉ GT\n
    file.write(b'\x4C\x41\x4E\x43\x49\x41\x20\x41\x55\x52\x45\x4C\x49\x41\x20\x42\x32\x30\x20\x43\x4F\x55\x50\xC3\x83\xC2\x89\x20\x47\x54\x0A')  # noqa: E501


with open('testdata/input8', 'w') as file:
    file.write(f'test@example.com:password1{linesep}')
    file.write(f'test@sub.example.com:password2{linesep}')
    file.write(f'test@example.ugur:password3{linesep}')
    file.write(f'test@sub.test-example.com:password4{linesep}')

with open('testdata/input9', 'wb') as file:
    # UTF-16
    file.write('16THEBEST!!!'.encode('utf-16') + f'{linesep}'.encode('utf-8'))
    # Russian
    file.write(f'!!!ееместной%%@!{linesep}'.encode('WINDOWS-1251'))

with open('testdata/input10', 'w') as file:
    file.write(f'cĳfer/Aa{linesep}')
    file.write(f'3M/Aa{linesep}')
    file.write(f'VERYVERYVERYVERYVERYVERYLONGLINE?{linesep}')

with open('testdata/input11', 'w') as file:
    file.write(f'cĳfer/Aa{linesep}')
    file.write(f'3M-test/Aa{linesep}')
    file.write(f'St. Maarten{linesep}')
    file.write(f'-Aai-Aai-/Aa{linesep}')
    file.write(f'3-hoekig{linesep}')
    file.write(f'Philipsburg.{linesep}')

with open('testdata/input12', 'wb') as file:
    file.write(b'\x57\x65\x73\x74\x2D\x46\x72\x79\x73\x6C\xC2\x89\x6E' + f'{linesep}'.encode('utf-8'))

with open('testdata/input13', 'w') as file:
    file.write(f'field1:field2:field3:field4:field5:field6:field7{linesep}')
    file.write(f'onefield{linesep}')

with open('testdata/input14', 'w') as file:
    file.write(f'field1:field2:field3:field4:field5:field6:field7{linesep}')
    file.write(f'onefield{linesep}')

with open('testdata/input15', 'w') as file:
    file.write(f'$HEX[5045d141524f4c]{linesep}')
    file.write(f'$HEX[51574552545955494f50c5]{linesep}')
    file.write(f'$HEX[5a73f3666932303030]{linesep}')
    file.write(f'$HEX[617261f16173]{linesep}')

with open('testdata/input16', 'w') as file:
    file.write(f'&#304;SMA&#304;L{linesep}')
    file.write(f'&#304;STANBUL{linesep}')
    file.write(f'&#351;ifreyok{linesep}')
    file.write(f'&gt;{linesep}')
    file.write(f'&alpha;{linesep}')

with open('testdata/input17', 'w') as file:
    file.write(f'&#304;SMA&#304;L{linesep}')
    file.write(f'&#304;STANBUL{linesep}')
    file.write(f'&#351;ifreyok{linesep}')
    file.write(f'&gt;{linesep}')
    file.write(f'&alpha;{linesep}')

with open('testdata/input18', 'w') as file:
    file.write(f'field1:field2:field3:field4:field5:field6:field7{linesep}')
    file.write(f'onefield{linesep}')

with open('testdata/input19', 'w') as file:
    file.write(f'line01{linesep}')
    file.write(f'line02{linesep}')
    file.write(f'line03{linesep}')
    file.write(f'line04{linesep}')
    file.write(f'line05{linesep}')
    file.write(f'line06{linesep}')
    file.write(f'line07{linesep}')
    file.write(f'line08{linesep}')
    file.write(f'line09{linesep}')
    file.write(f'line10{linesep}')

with open('testdata/input20', 'w') as file:
    file.write(f'Eselsbru"cke{linesep}')
    file.write(f'Fremdscha"men{linesep}')
    file.write(f'KA"SEHOCH{linesep}')

with open('testdata/input21', 'w') as file:
    file.write(f'user;password{linesep}')
    file.write(f'user2:password2{linesep}')
    file.write(f'user3----password3{linesep}')

with open('testdata/input22', 'w') as file:
    file.write(f'line1@example{linesep}')
    file.write(f'line2@example.com{linesep}')
    file.write(f'line3@ex-ample.com{linesep}')
    file.write(f'line4@ex.ample.com{linesep}')
    file.write(f'test@example.com:line5{linesep}')

with open('testdata/input23', 'w') as file:
    file.write(f'line1@example.com:baabe00a81fc405af4ab9b0f99615498{linesep}')
    file.write(f'line2@example.com:$h$7/uhfibmxg83yq6y1rh5y9wjee13kh.{linesep}')
    file.write(f'line3@example.com:$6$/fasjdfsadj$safjasdfasjdfasdjf/asdfsadfasdfasdfas/fadsfasdfa{linesep}')
    file.write(f'$1$Tx6cx/cA$ouWREOn7{linesep}')
    file.write(f'line5:changeme!{linesep}')
    file.write(f'line6:12345678{linesep}')
    file.write(f'line7:aaaaaa{linesep}')
    file.write(f'$aaa$test{linesep}')
    file.write(f'$H$8abc{linesep}')
    file.write(f'$2a$10$bcrypt{linesep}')
    file.write(f'$H$8abc{linesep}')
    file.write(f'$pizza$like{linesep}')

with open('testdata/input24', 'w') as file:
    file.write(f'line1@example.com,angus{linesep}')
    file.write(f'line2@example.com:snow{linesep}')
    file.write(f'line3@example.com:julia{linesep}')

with open('testdata/input25', 'w') as file:
    file.write(f'laténight{linesep}')
    file.write(f'thestrokes{linesep}')

with open('testdata/input26', 'w') as file:
    file.write(f'polopaç{linesep}')
    file.write(f'mündster{linesep}')

with open('testdata/input27', 'w') as file:
    file.write(f'rip-it.up{linesep}')
    file.write(f'orange juice{linesep}')

with open('testdata/input28', 'w') as file:
    file.write(f'stand_by_me{linesep}')
    file.write(f'the clash{linesep}')

with open('testdata/input29', 'w') as file:
    file.write(f'stand_by_me{linesep}')
    file.write(f'the clash{linesep}')
