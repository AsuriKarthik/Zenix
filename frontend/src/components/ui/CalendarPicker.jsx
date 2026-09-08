import React, { useState, useEffect, useRef } from 'react';
import { ChevronLeft, ChevronRight, ChevronsLeft, ChevronsRight, Calendar as CalendarIcon, X } from 'lucide-react';

const MONTH_NAMES = [
  'JANUARY', 'FEBRUARY', 'MARCH', 'APRIL', 'MAY', 'JUNE',
  'JULY', 'AUGUST', 'SEPTEMBER', 'OCTOBER', 'NOVEMBER', 'DECEMBER'
];

const WEEK_DAYS = ['Su', 'Mo', 'Tu', 'We', 'Th', 'Fr', 'Sa'];

/**
 * CalendarPicker Component
 * Interactive dark-themed popup calendar to shift through days, months, and years,
 * highlight days with ETW authentication activity, and filter audit logs.
 */
export default function CalendarPicker({
  selectedDate,
  onSelectDate,
  highlightDates = {}, // { 'YYYY-MM-DD': count }
  isOpen,
  onClose,
  style = {},
}) {
  const containerRef = useRef(null);

  // Initialize view date based on selectedDate or current date
  const initialDate = (() => {
    if (selectedDate && /^\d{4}-\d{2}-\d{2}$/.test(selectedDate)) {
      const [y, m, d] = selectedDate.split('-').map(Number);
      return new Date(y, m - 1, d);
    }
    return new Date();
  })();

  const [viewYear, setViewYear] = useState(initialDate.getFullYear());
  const [viewMonth, setViewMonth] = useState(initialDate.getMonth()); // 0-11
  const [viewMode, setViewMode] = useState('days'); // 'days' | 'months' | 'years'

  // Sync view when selectedDate changes externally
  useEffect(() => {
    if (selectedDate && /^\d{4}-\d{2}-\d{2}$/.test(selectedDate)) {
      const [y, m] = selectedDate.split('-').map(Number);
      setViewYear(y);
      setViewMonth(m - 1);
    }
  }, [selectedDate]);

  // Click outside to close
  useEffect(() => {
    if (!isOpen) return;
    const handleClickOutside = (e) => {
      if (containerRef.current && !containerRef.current.contains(e.target)) {
        onClose();
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  // Month navigation
  const prevMonth = () => {
    if (viewMonth === 0) {
      setViewMonth(11);
      setViewYear(y => y - 1);
    } else {
      setViewMonth(m => m - 1);
    }
  };

  const nextMonth = () => {
    if (viewMonth === 11) {
      setViewMonth(0);
      setViewYear(y => y + 1);
    } else {
      setViewMonth(m => m + 1);
    }
  };

  // Year navigation
  const prevYear = () => setViewYear(y => y - 1);
  const nextYear = () => setViewYear(y => y + 1);

  // Day grid calculations
  const firstDayOfWeek = new Date(viewYear, viewMonth, 1).getDay(); // 0 = Sunday
  const daysInCurrentMonth = new Date(viewYear, viewMonth + 1, 0).getDate();
  const daysInPreviousMonth = new Date(viewYear, viewMonth, 0).getDate();

  // Trailing days from previous month
  const prevMonthDays = [];
  for (let i = firstDayOfWeek - 1; i >= 0; i--) {
    prevMonthDays.push({
      day: daysInPreviousMonth - i,
      month: viewMonth === 0 ? 11 : viewMonth - 1,
      year: viewMonth === 0 ? viewYear - 1 : viewYear,
      isCurrentMonth: false,
    });
  }

  // Days in current month
  const currentMonthDays = [];
  for (let i = 1; i <= daysInCurrentMonth; i++) {
    currentMonthDays.push({
      day: i,
      month: viewMonth,
      year: viewYear,
      isCurrentMonth: true,
    });
  }

  // Leading days for next month to complete 35 or 42 grid cells
  const totalDaysSoFar = prevMonthDays.length + currentMonthDays.length;
  const targetTotal = totalDaysSoFar > 35 ? 42 : 35;
  const nextMonthDays = [];
  for (let i = 1; i <= targetTotal - totalDaysSoFar; i++) {
    nextMonthDays.push({
      day: i,
      month: viewMonth === 11 ? 0 : viewMonth + 1,
      year: viewMonth === 11 ? viewYear + 1 : viewYear,
      isCurrentMonth: false,
    });
  }

  const allCalendarDays = [...prevMonthDays, ...currentMonthDays, ...nextMonthDays];

  const formatPad = (n) => String(n).padStart(2, '0');

  const todayStr = (() => {
    const t = new Date();
    return `${t.getFullYear()}-${formatPad(t.getMonth() + 1)}-${formatPad(t.getDate())}`;
  })();

  return (
    <div
      ref={containerRef}
      style={{
        position: 'absolute',
        top: 'calc(100% + 8px)',
        right: -85,
        width: 320,
        backgroundColor: '#0E0E12',
        border: '1px solid rgba(255, 255, 255, 0.12)',
        borderRadius: 12,
        boxShadow: '0 20px 40px rgba(0, 0, 0, 0.85), 0 0 0 1px rgba(255, 255, 255, 0.05)',
        zIndex: 500,
        padding: '16px',
        fontFamily: 'var(--font-mono, monospace)',
        backdropFilter: 'blur(20px)',
        ...style,
      }}
    >
      {/* Header with Month/Year Navigation */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
          <button
            onClick={() => setViewMode(viewMode === 'months' ? 'days' : 'months')}
            className="btn btn-ghost btn-sm"
            style={{
              fontSize: 13,
              fontWeight: 700,
              letterSpacing: '0.05em',
              color: '#FFFFFF',
              padding: '4px 8px',
              fontFamily: 'var(--font-mono, monospace)',
            }}
            title="Switch month/year view"
          >
            {MONTH_NAMES[viewMonth]} {viewYear} ▾
          </button>
        </div>

        {/* Quick Shift Buttons */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <button
            onClick={prevYear}
            className="btn btn-ghost btn-sm"
            style={{ padding: '4px 6px', color: '#94A3B8' }}
            title="Previous year"
          >
            <ChevronsLeft size={14} />
          </button>
          <button
            onClick={prevMonth}
            className="btn btn-ghost btn-sm"
            style={{ padding: '4px 6px', color: '#94A3B8' }}
            title="Previous month"
          >
            <ChevronLeft size={14} />
          </button>
          <button
            onClick={nextMonth}
            className="btn btn-ghost btn-sm"
            style={{ padding: '4px 6px', color: '#94A3B8' }}
            title="Next month"
          >
            <ChevronRight size={14} />
          </button>
          <button
            onClick={nextYear}
            className="btn btn-ghost btn-sm"
            style={{ padding: '4px 6px', color: '#94A3B8' }}
            title="Next year"
          >
            <ChevronsRight size={14} />
          </button>
        </div>
      </div>

      {viewMode === 'months' ? (
        /* Month Selector Grid */
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 8, padding: '8px 0' }}>
          {MONTH_NAMES.map((mName, idx) => (
            <button
              key={mName}
              onClick={() => {
                setViewMonth(idx);
                setViewMode('days');
              }}
              style={{
                padding: '10px 4px',
                fontSize: 11,
                borderRadius: 6,
                border: idx === viewMonth ? '1px solid #38BDF8' : '1px solid rgba(255, 255, 255, 0.06)',
                backgroundColor: idx === viewMonth ? 'rgba(56, 189, 248, 0.15)' : 'rgba(255, 255, 255, 0.02)',
                color: idx === viewMonth ? '#38BDF8' : '#E2E8F0',
                cursor: 'pointer',
                fontWeight: 600,
              }}
            >
              {mName.slice(0, 3)}
            </button>
          ))}
        </div>
      ) : (
        /* Standard Days View */
        <>
          {/* Day of Week Headers */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(7, 1fr)', textAlign: 'center', marginBottom: 6 }}>
            {WEEK_DAYS.map(day => (
              <div
                key={day}
                style={{
                  fontSize: 11,
                  color: '#64748B',
                  fontWeight: 600,
                  padding: '4px 0',
                }}
              >
                {day}
              </div>
            ))}
          </div>

          {/* Days Grid */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(7, 1fr)', gap: 2 }}>
            {allCalendarDays.map((cell, index) => {
              const cellDateStr = `${cell.year}-${formatPad(cell.month + 1)}-${formatPad(cell.day)}`;
              const isSelected = selectedDate === cellDateStr;
              const isToday = cellDateStr === todayStr;
              const authCount = highlightDates[cellDateStr] || 0;
              const hasActivity = authCount > 0;

              return (
                <button
                  key={`${cellDateStr}-${index}`}
                  onClick={() => {
                    onSelectDate(cellDateStr);
                    onClose();
                  }}
                  title={hasActivity ? `${cellDateStr} (${authCount} ETW authentications)` : cellDateStr}
                  style={{
                    position: 'relative',
                    height: 36,
                    display: 'flex',
                    flexDirection: 'column',
                    alignItems: 'center',
                    justifyContent: 'center',
                    borderRadius: 6,
                    border: isToday && !isSelected ? '1px solid rgba(56, 189, 248, 0.4)' : 'none',
                    backgroundColor: isSelected
                      ? '#0284C7' // Matches the solid blue badge from the user's reference image
                      : hasActivity
                      ? 'rgba(34, 197, 94, 0.08)'
                      : 'transparent',
                    color: isSelected
                      ? '#FFFFFF'
                      : !cell.isCurrentMonth
                      ? '#475569'
                      : '#F1F5F9',
                    fontSize: 12,
                    fontWeight: isSelected || hasActivity ? 700 : 500,
                    cursor: 'pointer',
                    transition: 'all 0.15s ease',
                  }}
                  onMouseEnter={e => {
                    if (!isSelected) {
                      e.currentTarget.style.backgroundColor = 'rgba(255, 255, 255, 0.08)';
                    }
                  }}
                  onMouseLeave={e => {
                    if (!isSelected) {
                      e.currentTarget.style.backgroundColor = hasActivity ? 'rgba(34, 197, 94, 0.08)' : 'transparent';
                    }
                  }}
                >
                  <span>{cell.day}</span>
                  {/* Subtle dot indicator on days with authentications */}
                  {hasActivity && (
                    <span
                      style={{
                        position: 'absolute',
                        bottom: 3,
                        width: 4,
                        height: 4,
                        borderRadius: '50%',
                        backgroundColor: isSelected ? '#FFFFFF' : '#22C55E',
                      }}
                    />
                  )}
                </button>
              );
            })}
          </div>
        </>
      )}

      {/* Footer Controls */}
      <div
        style={{
          marginTop: 14,
          paddingTop: 10,
          borderTop: '1px solid rgba(255, 255, 255, 0.08)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
        }}
      >
        <button
          onClick={() => {
            onSelectDate('ALL');
            onClose();
          }}
          className="btn btn-ghost btn-sm"
          style={{
            fontSize: 11,
            color: selectedDate === 'ALL' ? '#38BDF8' : '#94A3B8',
            padding: '3px 8px',
          }}
        >
          All Days (Latest 10)
        </button>

        <button
          onClick={() => {
            onSelectDate(todayStr);
            onClose();
          }}
          className="btn btn-ghost btn-sm"
          style={{
            fontSize: 11,
            color: '#38BDF8',
            fontWeight: 600,
            padding: '3px 8px',
          }}
        >
          Today
        </button>
      </div>
    </div>
  );
}
