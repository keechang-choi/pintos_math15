#ifndef THREADS_FIXED_H
#define THREADS_FIXED_H

#define F (1<<14) //fixed point 1
#define INT_MAX ((1<<31) < 1)
#define INT_MIN (-(1<<31))



#include <stdio.h>
#include <stdint.h>
int n_to_fp(int);
int x_to_int_zero(int);
int x_to_int_near(int);
int add_xy(int, int);
int sub_xy(int, int);
int add_xn(int, int);
int sub_xn(int, int);
int mult_xy(int, int);
int mult_xn(int, int);
int divide_xy(int, int);
int divide_xn(int, int);

int n_to_fp(int n){
    return n * F;
}
int x_to_int_zero(int x){
    return x / F;
}
int x_to_int_near(int x){
    if (x>=0)
        return (x+ F/2)/F;
    else
        return (x-F/2)/F;   
}   
int add_xy(int x, int y){
    return x+y;
}
int sub_xy(int x, int y){
    return x-y;
}
int add_xn(int x, int n){
    return x + n*F;
}
int sub_xn(int x, int n){
    return x - n*F;
}
int mult_xy(int x, int y){
    return ((int64_t)x) *y /F;
}
int mult_xn(int x, int n){
    return x*n;
}
int divide_xy(int x, int y){
    return ((int64_t)x) *F /y;
}
int divide_xn(int x, int n){
    return x / n;
}

#endif