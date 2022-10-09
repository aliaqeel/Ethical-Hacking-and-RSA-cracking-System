#Extra Assingment
#Name: Ali Aqeel Zafar
#Neptune ID:AAFZDE
from math import gcd
from sympy import *
#took help from privacy practice as
def extendedeuclideanalgorithm(num1 , num2):
    #base case
    if num1 == 0:
        gcd = num2
        xold = 1
        yold = 0
        return gcd,yold,xold
    else:
        remainder = num2 % num1
        gcd, xnew, ynew = extendedeuclideanalgorithm(remainder, num1)
        quotient = num2 // num1
        xold = ynew - quotient * xnew
        yold = xnew
        return gcd,xold,yold

def calculateD(num1,num2):
    gcd, num, y = extendedeuclideanalgorithm(num1,num2)
    if num < 0:
        num = num + num2
    return num

#references for weiner attack
#https://www.youtube.com/watch?v=OpPrrndyYNU
#https://sagi.io/2016/04/crypto-classics-wieners-rsa-attack/
#https://en.wikipedia.org/wiki/Wiener%27s_attack
#http://monge.univ-mlv.fr/~jyt/Crypto/4/10.1.1.92.5261.pdf (used this to understand the logic behind the rational expressions)
def continued_fraction_and_rational_approximation(num1,num2):
    # the below code is used to find fractions e/N in their lowest form which is continued fraction.
    cfexpansion = []#list of quotients
    quotient = num1 // num2
    remainder = num1 % num2
    cfexpansion.append(quotient)
    while remainder != 0:
        num1 = num2
        num2 = remainder
        quotient = num1 // num2
        remainder = num1 % num2
        cfexpansion.append(quotient)

    # the below code is used to provide rational approximation or find k/d= phi(N)/d
    lenquotient = len(cfexpansion)
    Nominators = []
    Denominators = []
    for iter1 in range(lenquotient):
        if iter1 == 1:  # if quotient of the Number which is needed to approximated (m) is 1
            narr = cfexpansion[iter1] * cfexpansion[iter1 - 1] + 1  # (q[m-1] * q[m]) + 1
            darr = cfexpansion[iter1]  # predicted d might be from list of quotients.
        elif iter1 == 0:# if quotient of the Number which is needed to approximated (m) is 0
            narr = cfexpansion[iter1] # list of quotients of continue expression fractions this will be K
            darr = 1 # predicted d value
        else: # quotient of the Number which is needed to approximated (m) is even
            narr = cfexpansion[iter1]*Nominators[iter1-1] + Nominators[iter1-2] #((q[m - 1])*n[m-1]) + n[m-2]
            darr = cfexpansion[iter1]*Denominators[iter1-1] + Denominators[iter1-2] #((q[m - 1])*d[m-1]) + d[m-2]
        Nominators.append(narr) #predicted K values
        Denominators.append(darr) #predicted D values
        yield (narr,darr) #yield maintaining previous state of the tuple (narr,darr)
def weinerattack(n,e): #will run for key1 and key3
    #cf_expansions = continuedfractionexpansion(e, n)
    convergents = continued_fraction_and_rational_approximation(e,n)
    for k,d in convergents:
        if k == 0:
            continue;
        predictedphi = (e * d - 1) // k
        #Getting roots
        prime1 = Symbol('p', integer=True)
        roots = solve(prime1 ** 2 + (predictedphi - n - 1) * prime1 + n, prime1)
        if len(roots) == 2:
            prime1, prime2 = roots
            if prime1 * prime2 == n:
                print('p multiply by q is equal to n')
                phi = (prime1 - 1) * (prime2 - 1)  # calculate phi to calculate d through extended euclidean algorithm
                d = calculateD(e, phi)
                return prime1,prime2,d

#References for pollard p-1:
#https://stackoverflow.com/questions/16310871/how-to-find-d-given-p-q-and-e-in-rsa (to calculate d)
#https://gist.github.com/intrd/3f6e8f02e16faa54729b9288a8f59582
#https://en.wikipedia.org/wiki/Pollard%27s_p_%E2%88%92_1_algorithm
#https://www.youtube.com/watch?v=bI_Opi4KdXo
#https://www.calculatorsoup.com/calculators/math/prime-factors.php
def pollardpminus1(n, e): #will run for key2 and key4
    num1 = 2
    boundB = 2
    while True:
        num1 = pow(num1, boundB, n)
        prime1 = gcd(num1 - 1, n)
        if prime1>1 and prime1<n: #checking if 1st prime is between 1 and n
            prime2 = int(n // prime1)
            phi = (prime1 - 1) * (prime2 - 1) #calculate phi to calculate d through extended euclidean algorithm
            d = calculateD(e, phi)
            return prime1,prime2,d
        boundB= boundB + 1

def main():
    n = int(input('Enter N:'))
    e = int(input('Enter e:'))
    if e <= 65537:
        print('pollard p-1:')
        p,q,d = pollardpminus1(n,e)
        print('d:', d)
        print('p:', p)
        print('q:', q)
        if (p*q == n):
            print('p multiply by q is equal to n')
        m = 12
        tempm = pow(m,e,n)
        temp = pow(tempm,int(d),n)
        if temp == m:
            print('message:',temp) #output message for the correctness of the attack
            print('RSA Correctness holds')
    else:
        print('Weiner Attack:')
        p, q, d = weinerattack(n, e)
        print('d:', d)
        print('p:', p)
        print('q:', q)
        m = 12
        tempm = pow(m, e, n)
        temp = pow(tempm, int(d), n)
        if temp == m:
            print('message:', temp)  # output message for the correctness of the attack
            print('RSA Correctness holds')



main()

