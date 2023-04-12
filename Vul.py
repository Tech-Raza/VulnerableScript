import pandas as pd
import fileinput
import os

failure = ['failure']
success = ['success']
successOrNot = {0: failure, 1: success}

if __name__ == '__main__':
    print(failure)
    print(success)
    print(successOrNot)
    try:
        df = pd.read_csv('D:\\Downloads\\VulnerableApp_Gradle\\Scanner\\sast\\expectedIssues.csv', header=0)

        for fileNum, file in enumerate(df['File']):
            try:
                path = 'D:\Downloads\VulnerableApp_Gradle'
                pathFinal = os.path.join(path, file)

                indexStart = int(int(df['Line'][fileNum]) - 2) # Line No
                commentStart = "// start : Expecting " + str(df['CWE'][fileNum])
                indexEnd = int(int(df['Line'][fileNum]) + 2) # 44
                commentEnd = "// End: " + str(df['CWE'][fileNum])

                for lineNum, line in enumerate(fileinput.input(pathFinal, inplace=1)):
                    if lineNum == indexStart:
                        print(commentStart)
                    if lineNum == indexEnd:
                        print(commentEnd)

                    print(line.rstrip())
                success.append(pathFinal)

            except FileNotFoundError as f:
                print("File is not found. Please either check the path mentioned or location where file is assumed to "
                      "be present: \n" + str(f))
                # successOrNot.update(0, failure.append(pathFinal))
                failure.append(pathFinal)

            except KeyError as k:
                print("Key mentioned is not correct: " + str(k))
                failure.append(pathFinal)

            except Exception as e:
                print(e)
                failure.append(pathFinal)

    except Exception as e:
        print(e)
        failure.appned('csvNotFound')

    print(successOrNot)
    print("The number of failed records are: "+str(len(failure)-1))
    print("The number of successful records are: "+str(len(success)-1))
    # successOrNot.update((1, success.append(pathFinal)))
