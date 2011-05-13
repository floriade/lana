#!/usr/bin/gnuplot

set grid
set title "Packet Processing Engine"
set xlabel "Packets"
set ylabel "Processing Time in us"
set xtics nomirror rotate by -45
set ytics border in scale 0,0 mirror norotate offset character 0, 0, 0
set border 3
set grid y linestyle 4
set xrange [1:150000]
#set log y
set key below

set style line 1 lw 3 lt 1
set style line 2 lw 3 lt 2
set style line 3 lw 3 lt 3
set style line 4 lw 3 lt 4
set style line 5 lw 3 lt 5
set style line 6 lw 3 lt 6

#set terminal png size 1024.768
set terminal pdf monochrome dashed font ",6"
set output 'out.pdf'

plot "gnuplot.dat" using 1:2 title "sched single, 1 CPU" with lines ls 1, \
     "gnuplot.dat" using 1:3 title "sched rr, 2 CPUs" with lines ls 2, \
     "gnuplot.dat" using 1:4 title "sched rr, 4 CPUs" with lines ls 3

