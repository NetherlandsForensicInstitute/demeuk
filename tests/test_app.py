import sys
from unittest.mock import patch

from bin.demeuk import main
from pytest import raises

from subprocess import PIPE, run


def calculate_line_numbers(file_name):
    lines = 0
    with open(file_name, 'rb') as file:
        for lines, line in enumerate(file):
            pass
    return lines + 1


def test_demeuk():
    testargs = ['demeuk', '-i', 'testdata/input1', '-o', 'testdata/output1', '-l', 'testdata/log1', '--leak']
    with patch.object(sys, 'argv', testargs):
        main()

    line_num_input1 = calculate_line_numbers('testdata/input1')
    line_num_output1 = calculate_line_numbers('testdata/output1')
    line_num_log1 = calculate_line_numbers('testdata/log1')

    assert line_num_log1 == 5
    assert line_num_output1 == 9
    assert line_num_input1 == (line_num_output1 + line_num_log1 - 1)
    with open('testdata/output1') as file:
        filecontent = file.read()
        assert 'Password123!@"\n' in filecontent
        assert 'ǓǝǪǼȧɠ\n' in filecontent
        assert 'ʄʛʨʾϑϡϣЄ\n' in filecontent
        assert 'ϽϾϿЀЁЂЃЄЅІЇЈ\n' in filecontent
        assert '做戏之说\n' in filecontent
        assert 'Hyggelig123åmøtedeg!\n' in filecontent
        assert 'бонусов$123\n' in filecontent
        assert '!!!ееместной%%@!\n' in filecontent


def test_multithread():
    testargs = ['demeuk', '-i', 'testdata/input2', '-o', 'testdata/output2', '-j', '3']
    with patch.object(sys, 'argv', testargs):
        main()

    line_num_input1 = calculate_line_numbers('testdata/input2')
    line_num_output1 = calculate_line_numbers('testdata/output2')

    assert line_num_output1 == 8
    assert line_num_input1 == line_num_output1


def test_newline():
    testargs = ['demeuk', '-i', 'testdata/input3', '-o', 'testdata/output3']
    with patch.object(sys, 'argv', testargs):
        main()

    line_num_input1 = calculate_line_numbers('testdata/input3')
    line_num_output1 = calculate_line_numbers('testdata/output3')

    assert line_num_output1 == 8
    assert line_num_input1 == line_num_output1
    with open('testdata/output3') as file:
        filecontent = file.read()
        for x in range(7):
            assert f'line{x}\n' in filecontent


def test_tabchar():
    testargs = ['demeuk', '-i', 'testdata/input4', '-o', 'testdata/output4', '--tab']
    with patch.object(sys, 'argv', testargs):
        main()

    line_num_output1 = calculate_line_numbers('testdata/output4')
    assert line_num_output1 == 2
    with open('testdata/output4') as file:
        filecontent = file.read()
        assert 'line:entry\n' in filecontent
        assert 'line2:entry2\n' in filecontent


def test_split_email():
    testargs = ['demeuk', '-i', 'testdata/input5', '-o', 'testdata/output5', '--remove-email', '-c']
    with patch.object(sys, 'argv', testargs):
        main()
    line_num_output = calculate_line_numbers('testdata/output5')
    assert line_num_output == 6
    with open('testdata/output5') as file:
        filecontent = file.read()
        assert 'line1\n' in filecontent
        assert 'email@example.com' not in filecontent
        assert 'alcatel-sbell' not in filecontent
        assert '\nline4\n' in filecontent
        assert '\nline5\n' in filecontent
        assert '\nline6\n' in filecontent


def test_googlengram():
    testargs = ['demeuk', '-i', 'testdata/input6', '-o', 'testdata/output6', '-g']
    with patch.object(sys, 'argv', testargs):
        main()
    line_num_output = calculate_line_numbers('testdata/output6')
    assert line_num_output == 4
    with open('testdata/output6') as f:
        filecontent = f.read()
        assert 'I\'ain\n' in filecontent
        assert 'I\'Afrique occidental\n' in filecontent
        assert 'I\'Allemagne\n' in filecontent
        assert 'I\'ain a\n' in filecontent


def test_coupe():
    testargs = ['demeuk', '-i', 'testdata/input7', '-o', 'testdata/output7', '-l', 'testdata/log7', '--mojibake']
    with patch.object(sys, 'argv', testargs):
        main()

    line_num_output = calculate_line_numbers('testdata/output7')
    assert line_num_output == 2
    with open('testdata/output7') as f:
        filecontent = f.read()
        assert 'coupÉ' in filecontent
        assert 'LANCIA AURELIA B20 COUPÉ GT\n' in filecontent


def test_cut():
    testargs = ['demeuk', '-i', 'testdata/input8', '-o', 'testdata/output8', '-c']
    with patch.object(sys, 'argv', testargs):
        main()

    line_num_output = calculate_line_numbers('testdata/output8')
    assert line_num_output == 4
    with open('testdata/output8') as f:
        filecontent = f.read()
        assert 'example.com' not in filecontent
        assert 'sub.example.com' not in filecontent
        assert 'example.guru' not in filecontent
        assert 'sub.test-example.com' not in filecontent


def test_output_encoding():
    testargs = ['demeuk', '-i', 'testdata/input1', '-o', 'testdata/output1', '--output-encoding', 'C', '--encode']
    with patch.object(sys, 'argv', testargs):
        with raises(UnicodeEncodeError):
            main()


def test_input_encoding():
    testargs = ['demeuk', '-i', 'testdata/input9', '-o', 'testdata/output9',
                '--input-encoding', 'windows-1251,UTF-16', '--encode']
    with patch.object(sys, 'argv', testargs):
        main()
    line_num_output = calculate_line_numbers('testdata/output9')
    assert line_num_output == 2
    with open('testdata/output9') as f:
        filecontent = f.read()
        assert '16THEBEST!!!\n' in filecontent
        assert '!!!ееместной%%@!\n' in filecontent


def test_delimiter():
    testargs = [
        'demeuk', '-i', 'testdata/input10', '-o', 'testdata/output10',
        '-l', 'testdata/log10',
        '--cut', '--delimiter', '/', '--cut-before', '--check-min-length', '1',
        '--check-max-length', '10',
        '--check-case',
    ]
    with patch.object(sys, 'argv', testargs):
        main()
    line_num_output = calculate_line_numbers('testdata/output10')
    assert line_num_output == 1
    with open('testdata/output10') as f:
        filecontent = f.read()
        assert 'cĳfer\n' in filecontent
        assert '3M\n' not in filecontent
        assert 'VERYVERYVERYVERYVERYVERYLONGLINE?\n' not in filecontent


def test_language_processing():
    testargs = [
        'demeuk', '-i', 'testdata/input11', '-o', 'testdata/output11',
        '-l', 'testdata/log11',
        '--cut', '--delimiter', '/', '--cut-before', '--check-min-length', '2',
        '--remove-strip-punctuation', '--add-lower', '--add-latin-ligatures',
        '--add-split',
    ]
    with patch.object(sys, 'argv', testargs):
        main()
    line_num_output = calculate_line_numbers('testdata/output11')
    assert line_num_output == 29
    with open('testdata/output11') as f:
        filecontent = f.read()
        assert 'cĳfer\n' in filecontent
        assert 'cijfer\n' in filecontent
        assert '3M\n' in filecontent
        assert '3m\n' in filecontent
        assert '\ntest\n' in filecontent
        assert '3M-test\n' in filecontent
        assert 'St. Maarten\n' in filecontent
        assert 'St\n' in filecontent
        assert '\nMaarten\n' in filecontent
        assert 'Aai-Aai\n' in filecontent
        assert '3-hoekig\n' in filecontent
        assert '\nhoekig\n' in filecontent
        assert '3\n' not in filecontent
        assert 'Philipsburg.\n' not in filecontent
        assert 'Philipsburg\n' in filecontent


def test_fries():
    testargs = ['demeuk', '-i', 'testdata/input12', '-o', 'testdata/output12',
                '-l', 'testdata/log12', '--encode', '--check-controlchar']
    with patch.object(sys, 'argv', testargs):
        main()
    with open('testdata/log12') as f:
        filecontent = f.read()
        assert 'West-Frysl' in filecontent
    with open('testdata/output12') as f:
        filecontent = f.read()
        assert 'West-Frysl‰n' not in filecontent


def test_cut_fields():
    testargs = [
        'demeuk', '-i', 'testdata/input13', '-o', 'testdata/output13', '-l', 'testdata/log13',
        '-f', '5-', '-c',
    ]
    with patch.object(sys, 'argv', testargs):
        main()
    with open('testdata/output13') as f:
        filecontent = f.read()
        assert 'field5:field6:field7\n' in filecontent
        assert 'field4' not in filecontent


def test_cut_fields_single():
    testargs = [
        'demeuk', '-i', 'testdata/input14', '-o', 'testdata/output14', '-l', 'testdata/log14',
        '-f', '5', '-c',
    ]
    with patch.object(sys, 'argv', testargs):
        main()
    with open('testdata/output14') as f:
        filecontent = f.read()
        assert 'field5\n' in filecontent
        assert 'field4' not in filecontent


def test_unhex():
    testargs = [
        'demeuk', '-i', 'testdata/input15', '-o', 'testdata/output15', '-l', 'testdata/log15',
        '--hex', '--encode',
    ]
    with patch.object(sys, 'argv', testargs):
        main()
    with open('testdata/output15') as f:
        filecontent = f.read()
        assert 'PEÑAROL\n' in filecontent
        assert 'QWERTYUIOPÅ\n' in filecontent
        assert 'Zsófi2000\n' in filecontent
        assert 'arañas\n' in filecontent
        assert '$HEX[' not in filecontent


def test_unhtml():
    testargs = [
        'demeuk', '-i', 'testdata/input16', '-o', 'testdata/output16', '-l', 'testdata/log16',
        '--html',
    ]
    with patch.object(sys, 'argv', testargs):
        main()
    with open('testdata/output16') as f:
        filecontent = f.read()
        assert 'İSMAİL\n' in filecontent
        assert 'İSTANBUL\n' in filecontent
        assert 'şifreyok\n' in filecontent
        assert 'α\n' not in filecontent
        assert '&gt;\n' in filecontent


def test_unhtml_named():
    testargs = [
        'demeuk', '-i', 'testdata/input17', '-o', 'testdata/output17', '-l', 'testdata/log17',
        '--html', '--html-named',
    ]
    with patch.object(sys, 'argv', testargs):
        main()
    with open('testdata/output17') as f:
        filecontent = f.read()
        assert 'İSMAİL\n' in filecontent
        assert 'İSTANBUL\n' in filecontent
        assert 'şifreyok\n' in filecontent
        assert 'α\n' in filecontent
        assert '>\n' in filecontent


def test_verbose():
    testargs = [
        'demeuk', '-i', 'testdata/input18', '-o', 'testdata/output18', '-l', 'testdata/log18',
        '-f', '5-', '-c', '--verbose', '--debug'
    ]
    with patch.object(sys, 'argv', testargs):
        main()
    with open('testdata/log18') as f:
        filecontent = f.read()
        assert 'Clean_cut; ' in filecontent


def test_limit():
    testargs = [
        'demeuk', '-i', 'testdata/input19', '-o', 'testdata/output19', '-l', 'testdata/log19',
        '--limit', '5',
    ]
    with patch.object(sys, 'argv', testargs):
        main()

    line_num_output = calculate_line_numbers('testdata/output19')
    assert line_num_output == 5


def test_clean_add_umlaut():
    testargs = [
        'demeuk', '-i', 'testdata/input20', '-o', 'testdata/output20', '-l', 'testdata/log20',
        '--add-umlaut', '--verbose', '--encode'
    ]
    with patch.object(sys, 'argv', testargs):
        main()

    with open('testdata/output20') as f:
        filecontent = f.read()
        assert 'Eselsbrücke' in filecontent
        assert 'Fremdschämen' in filecontent
        assert 'KÄSEHOCH' in filecontent
        assert 'KA"SEHOCH' in filecontent

    testargs = [
        'demeuk', '-i', 'testdata/input20', '-o', 'testdata/output20.2', '-l', 'testdata/log20.2',
        '--umlaut', '--verbose',
    ]
    with patch.object(sys, 'argv', testargs):
        main()

    with open('testdata/output20.2') as f:
        filecontent = f.read()
        assert 'Eselsbrücke' in filecontent
        assert 'Fremdschämen' in filecontent
        assert 'KÄSEHOCH' in filecontent
        assert 'KA"SEHOCH' not in filecontent


def test_multiple_delimiters():
    testargs = [
        'demeuk', '-i', 'testdata/input21', '-o', 'testdata/output21', '-l', 'testdata/log20',
        '-c', '--verbose', '-d', ':,;,----',
    ]
    with patch.object(sys, 'argv', testargs):
        main()

    with open('testdata/output21') as f:
        filecontent = f.read()
        assert 'password\n' in filecontent
        assert 'password2\n' in filecontent
        assert 'password3\n' in filecontent
        assert 'user' not in filecontent


def test_check_email():
    testargs = [
        'demeuk', '-i', 'testdata/input22', '-o', 'testdata/output22', '-l', 'testdata/log22',
        '--verbose', '--check-email', '--remove-email',
    ]
    with patch.object(sys, 'argv', testargs):
        main()

    with open('testdata/output22') as f:
        filecontent = f.read()
        assert 'line1' in filecontent
        assert 'line2' not in filecontent
        assert 'line3' not in filecontent
        assert 'line4' not in filecontent
        assert 'line5\n' in filecontent


def test_check_hash():
    testargs = [
        'demeuk', '-i', 'testdata/input23', '-o', 'testdata/output23', '-l', 'testdata/log23',
        '--verbose', '--check-hash', '-c',
    ]
    with patch.object(sys, 'argv', testargs):
        main()
    with open('testdata/output23') as f:
        filecontent = f.read()
        assert 'baabe00a81fc405af4ab9b0f99615498' not in filecontent
        assert '$h$7/uhfibmxg83yq6y1rh5y9wjee13kh.' not in filecontent
        assert '$6$/fasjdfsadj$safjasdfasjdfa' not in filecontent
        assert '$1$Tx6cx/cA$ouWREOn7' not in filecontent
        assert 'changeme!' in filecontent
        assert 'line5' not in filecontent
        assert '12345678' in filecontent
        assert 'aaaaaa' in filecontent
        assert '$aaa$test' in filecontent
        assert '$H$8abc' in filecontent
        assert '$2a$10$bcrypt' not in filecontent
        assert '$pizza$like' in filecontent


def test_check_bug_comma_d():
    testargs = [
        'demeuk', '-i', 'testdata/input24', '-o', 'testdata/output24', '-l', 'testdata/log24',
        '--verbose', '-c', '-d', ',;:',
    ]
    with patch.object(sys, 'argv', testargs):
        main()
    with open('testdata/output24') as f:
        filecontent = f.read()
        assert 'line1' not in filecontent
        assert 'angus' in filecontent
        assert 'line2' not in filecontent
        assert 'snow' in filecontent


def test_check_non_ascii():
    testargs = [
        'demeuk', '-i', 'testdata/input25', '-o', 'testdata/output25', '-l', 'testdata/log25',
        '--verbose', '--check-non-ascii',
    ]
    with patch.object(sys, 'argv', testargs):
        main()
    with open('testdata/output25') as f:
        filecontent = f.read()
        assert 'laténight' not in filecontent
        assert 'thestrokes' in filecontent


def test_clean_non_ascii():
    testargs = [
        'demeuk', '-i', 'testdata/input26', '-o', 'testdata/output26', '-l', 'testdata/log26',
        '--verbose', '--non-ascii',
    ]
    with patch.object(sys, 'argv', testargs):
        main()
    with open('testdata/output26') as f:
        filecontent = f.read()

        assert 'polopaç' not in filecontent
        assert 'mündster' not in filecontent
        assert 'polopac' in filecontent
        assert 'mundster' in filecontent


def test_remove_punctuation():
    testargs = [
        'demeuk', '-i', 'testdata/input27', '-o', 'testdata/output27', '-l', 'testdata/log27',
        '--verbose', '--remove-punctuation',
    ]
    with patch.object(sys, 'argv', testargs):
        main()
    with open('testdata/output27') as f:
        filecontent = f.read()

        assert 'ripitup' in filecontent
        assert 'orangejuice' in filecontent


def test_remove_different_punctuation():
    testargs = [
        'demeuk', '-i', 'testdata/input28', '-o', 'testdata/output28', '-l', 'testdata/log28',
        '--verbose', '--remove-punctuation', '--punctuation', '_',
    ]
    with patch.object(sys, 'argv', testargs):
        main()
    with open('testdata/output28') as f:
        filecontent = f.read()

        assert 'standbyme' in filecontent
        assert 'the clash' in filecontent


def test_add_without_punctuation():
    testargs = [
        'demeuk', '-i', 'testdata/input29', '-o', 'testdata/output29', '-l', 'testdata/log29',
        '--verbose', '--add-without-punctuation',
    ]
    with patch.object(sys, 'argv', testargs):
        main()
    with open('testdata/output29') as f:
        filecontent = f.read()

        assert 'stand_by_me' in filecontent
        assert 'the clash' in filecontent
        assert 'standbyme' in filecontent
        assert 'theclash' in filecontent


def test_glob():
    testargs = [
        'demeuk', '-i', 'testdata/input*', '-o', 'testdata/output30', '-l', 'testdata/log30',
        '--verbose', '-c', '-d', ',;:',
    ]
    with patch.object(sys, 'argv', testargs):
        main()
    with open('testdata/output30') as f:
        assert len(f.readlines()) > 100


def test_bug_html_control():
    testargs = [
        'demeuk', '-i', 'testdata/input31', '-o', 'testdata/output31', '-l', 'testdata/log31',
        '--verbose', '--html', '--check-controlchar'
    ]
    with patch.object(sys, 'argv', testargs):
        main()
    with open('testdata/output31') as f:
        filecontent = f.read()
        assert '\x0c\x0c' not in filecontent


def test_bug_dollar_line():
    testargs = [
        'demeuk', '-i', 'testdata/input32', '-o', 'testdata/output32', '-l', 'testdata/log32',
        '--verbose', '--check-hash',
    ]
    with patch.object(sys, 'argv', testargs):
        main()
    with open('testdata/output32') as f:
        filecontent = f.read()
        assert '$1$2$3$4' in filecontent
        assert '$1$money$1$' in filecontent
        assert '$1$ilovepizza' in filecontent
        assert '$1$1+l0l$aaaaaaaaaaaa./' not in filecontent
        assert '$4$4$4pizza' in filecontent


def test_check_replacement_character():
    testargs = [
        'demeuk', '-i', 'testdata/input33', '-o', 'testdata/output33', '-l', 'testdata/log33',
        '--verbose', '--check-replacement-character',
    ]
    with patch.object(sys, 'argv', testargs):
        main()
    with open('testdata/output33') as f:
        filecontent = f.read()
        assert 'invalidstring�' not in filecontent
        assert 'jungejunge' in filecontent


def test_email_detection():
    testargs = [
        'demeuk', '-i', 'testdata/input34', '-o', 'testdata/output34', '-l', 'testdata/log34',
        '--verbose', '--check-email',
    ]
    with patch.object(sys, 'argv', testargs):
        main()
    with open('testdata/output34') as f:
        filecontent = f.read()
        assert 'bar@example.com' not in filecontent
        assert 'foo@example.com' not in filecontent
        assert 'p@ssW0rd.me@Home' not in filecontent
        assert 'w@ssB0rd.we' not in filecontent
        assert 'P@ssw0rd.1' in filecontent
        assert 'cr@ssT0rd' in filecontent
        assert 'p@..w0rd' in filecontent


def test_newline_replacement():
    testargs = [
        'demeuk', '-i', 'testdata/input35', '-o', 'testdata/output35', '-l', 'testdata/log35',
        '--verbose', '--hex', '--html',
    ]
    with patch.object(sys, 'argv', testargs):
        main()
    with open('testdata/output35') as f:
        filecontent = f.read()
        assert 'Avocado\n' in filecontent
        assert '\nBanana\\r\\n\n' in filecontent
        assert '\nCoconut\\n\n' in filecontent
        assert '\nDragonfruit\n' in filecontent
        assert '\nElderberry\n' in filecontent
        assert '\nFig<br>\n' in filecontent
        assert '\nGrapefruit\n' in filecontent
        assert '\nHoneyberry\n' in filecontent
        assert '\nIcaco\n' in filecontent
        assert '\nJambul' in filecontent


def test_trim():
    testargs = [
        'demeuk', '-i', 'testdata/input36', '-o', 'testdata/output36', '-l', 'testdata/log36',
        '--verbose', '--hex', '--html', '--trim',
    ]
    with patch.object(sys, 'argv', testargs):
        main()
    with open('testdata/output36') as f:
        filecontent = f.read()
        assert 'angleball\n' in filecontent
        assert '\nbadminton\n' in filecontent
        assert '\ncrossminton\n' in filecontent
        assert '\ndodgeball\n' in filecontent
        assert '\nfrontenis\n' in filecontent
        assert '\ngoalball\n' in filecontent
        assert '\nhandball\n' in filecontent
        assert '\ninter<br>crosse\n' in filecontent
        assert '\njok\\ngu\n' in filecontent
        assert '\nkickball\n' in filecontent
        assert '\nlacrosse\n' in filecontent
        assert '\nnetball\n' in filecontent
        assert '\npadbol\n' in filecontent
        assert '\nroque\n' in filecontent
        assert '\nsnooker\n' in filecontent
        assert '\ntchoukball\n' in filecontent
        assert '\nvigoro' in filecontent


def test_invalid_unhex():
    testargs = [
        'demeuk', '-i', 'testdata/input37', '-o', 'testdata/output37', '-l', 'testdata/log37',
        '--verbose', '--hex',
    ]
    with patch.object(sys, 'argv', testargs):
        main()

    with open('testdata/output37') as f:
        filecontent = f.read()
        # Invalid hex string, leaving at as is.
        assert '$HEX[e]tiredofwaiting\n' in filecontent
        # Invalid hex string, leaving at as is.
        assert '\n$HEX[eee]\n' in filecontent
        # This is a valid hash, but it is not a hex string from start to end.
        assert '\n$HEX[6C657469746B69636B696E]123!\n' in filecontent
        # Valid upcase test
        assert '\nlosingtouch\n' in filecontent


def test_skip():
    testargs = [
        'demeuk', '-i', 'testdata/input38', '-o', 'testdata/output38', '-l', 'testdata/log38',
        '--verbose', '--skip', '1'
    ]
    with patch.object(sys, 'argv', testargs):
        main()

    with open('testdata/output38') as f:
        filecontent = f.read()

    assert '112345678' not in filecontent


def test_check_starting_with():
    testargs = [
        'demeuk', '-i', 'testdata/input39', '-o', 'testdata/output39', '-l', 'testdata/log39',
        '--verbose', '--check-starting-with', '/,#,:', '--tab'
    ]
    with patch.object(sys, 'argv', testargs):
        main()

    with open('testdata/output39') as f:
        filecontent = f.read()

    assert 'firstlovesong' not in filecontent
    assert 'secondlovesong' not in filecontent
    assert 'californiastars' not in filecontent
    assert '\n\n' in filecontent


def test_check_empty_line():
    testargs = [
        'demeuk', '-i', 'testdata/input40', '-o', 'testdata/output40', '-l', 'testdata/log40',
        '--verbose', '--check-empty-line',
    ]
    with patch.object(sys, 'argv', testargs):
        main()

    with open('testdata/output40') as f:
        filecontent = f.read()

    assert '\n\n' not in filecontent


def test_check_mac_address():
    testargs = [
        'demeuk', '-i', 'testdata/input41', '-o', 'testdata/output41', '-l', 'testdata/log41',
        '--verbose', '--check-mac-address',
    ]
    with patch.object(sys, 'argv', testargs):
        main()

    with open('testdata/output41') as f:
        filecontent = f.read()

    assert '2C:C5:D3:70:78:2c' not in filecontent
    assert 'dummy' in filecontent


def test_check_uuid():
    testargs = [
        'demeuk', '-i', 'testdata/input42', '-o', 'testdata/output42', '-l', 'testdata/log42',
        '--verbose', '--check-uuid',
    ]
    with patch.object(sys, 'argv', testargs):
        main()

    with open('testdata/output42') as f:
        filecontent = f.read()

    assert 'd4662e44-00f1-4ef6-857e-76e3c61604cd' not in filecontent
    assert 'D4662E44-00F1-4EF6-857E-76E3C61604CD' not in filecontent
    assert 'dummy' in filecontent


def test_check_ending_with():
    testargs = [
        'demeuk', '-i', 'testdata/input43', '-o', 'testdata/output43', '-l', 'testdata/log43',
        '--verbose', '--check-ending-with', '.jpg,@whatsapp.com',
    ]
    with patch.object(sys, 'argv', testargs):
        main()

    with open('testdata/output43') as f:
        filecontent = f.read()

    assert 'test.jpg' not in filecontent
    assert 'hello@whatsapp.com' not in filecontent
    assert 'dummy' in filecontent


def test_check_title_case():
    testargs = [
        'demeuk', '-i', 'testdata/input44', '-o', 'testdata/output44', '-l', 'testdata/log44',
        '--verbose', '--title-case',
    ]
    with patch.object(sys, 'argv', testargs):
        main()

    with open('testdata/output44') as f:
        filecontent = f.read()

    assert '3 Doors Down' in filecontent


def test_leak_full():
    testargs = [
        'demeuk', '-i', 'testdata/input45', '-o', 'testdata/output45', '-l', 'testdata/log45',
        '--verbose', '--leak-full',
    ]
    with patch.object(sys, 'argv', testargs):
        main()

    with open('testdata/output45') as f:
        filecontent = f.read()

    # Test for mojibake
    assert 'coupÉ' in filecontent
    # Test for encode
    assert '!!!ееместной%%@!' in filecontent
    # Test for control-char
    assert '\x01' not in filecontent
    # Test for newline and html
    assert '\nnewline\n' in filecontent
    # Test for html named
    assert '<html_named>' in filecontent
    # Test for md5 hash
    assert '919c7e5fe31e73c7acbad69af9dbc4f5' not in filecontent
    # Test for hex
    assert 'Elderberry' in filecontent
    # Test for mac-address
    assert '00:11:22:33:44:55' not in filecontent
    # Test for uuid
    assert '123e4567-e89b-12d3-a456-426655440000' not in filecontent
    # Test for removing e-mail
    assert 'demeuk@example.com' not in filecontent
    # Test for replacement character
    assert '�' not in filecontent
    # Test for empty line
    assert '\n\n' not in filecontent


def test_check_regex():
    testargs = [
        'demeuk', '-i', 'testdata/input46', '-o', 'testdata/output46', '-l', 'testdata/log46',
        '--verbose', '--check-regex', '^[a-z]{3}$',
    ]
    with patch.object(sys, 'argv', testargs):
        main()

    with open('testdata/output46') as f:
        filecontent = f.read()

    assert 'abc' in filecontent
    assert 'abcd' not in filecontent
    assert 'a\n' not in filecontent
    assert 'ab\n' not in filecontent
    assert 'aBc' not in filecontent
    assert '123' not in filecontent


def test_check_multiple_regexes():
    testargs = [
        'demeuk', '-i', 'testdata/input47', '-o', 'testdata/output47', '-l', 'testdata/log47',
        '--verbose', '--check-regex', '\\d,\\w',
    ]

    with patch.object(sys, 'argv', testargs):
        main()

    with open('testdata/output47') as f:
        filecontent = f.read()

    assert 'alpha\n' not in filecontent
    assert 'alpha123\n' in filecontent
    assert 'alpha1234!' in filecontent


def test_stdin_stdout():
    comlist = ['bin/demeuk.py']
    script = b'input\nlines\n'
    res = run(comlist, input=script,
              stdout=PIPE, stderr=PIPE)
    assert res.returncode == 0
    assert res.stdout == b'input\nlines\n'
    assert res.stderr == b''


def test_check_lowercase():
    testargs = [
        'demeuk', '-i', 'testdata/input48', '-o', 'testdata/output48', '-l', 'testdata/log48',
        '--verbose', '--lowercase',
    ]
    with patch.object(sys, 'argv', testargs):
        main()

    with open('testdata/output48') as f:
        filecontent = f.read()

    assert '3 doors down' in filecontent


def test_split():
    testargs = [
        'demeuk', '-i', 'testdata/input49', '-o', 'testdata/output49', '-l', 'testdata/log49',
        '--verbose', '--split',
    ]
    with patch.object(sys, 'argv', testargs):
        main()

    with open('testdata/output49') as f:
        filecontent = f.read()

    assert 'Thirty\nSeconds\n' in filecontent
