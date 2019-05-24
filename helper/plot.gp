#!/usr/bin/gnuplot --persist
# ARG0: plot.gp
# ARG1: input source filename (generate by flowimpaler)
# ARG2: output filename

set title "Dist."
set xlabel "Label"
set ylabel "Volume"
set terminal png font " Times_New_Roman,12 " size 1920, 1080
set output ARG2

# Set xtic & xlabel 
# set xtics rotate by 45 right
set auto x 
set style data histogram
set style fill solid border -1

set xtics rotate by 45 right
set key right 
set rmargin 5

# Plot 
plot ARG1 u 2:xticlabels(1) lc rgb "#FF0000" title "Dist. from pcap"
