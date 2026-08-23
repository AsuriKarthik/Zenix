import { create } from 'zustand';

const useLoadingStore = create((set) => ({
  activeCount: 0,
  routeActive: false,
  isLoading: false,
  loadKey: 0,

  startRequest: () => set((state) => {
    const nextCount = state.activeCount + 1;
    return {
      activeCount: nextCount,
      isLoading: true,
      loadKey: nextCount === 1 ? state.loadKey + 1 : state.loadKey,
    };
  }),

  endRequest: () => set((state) => {
    const nextCount = Math.max(0, state.activeCount - 1);
    return {
      activeCount: nextCount,
      isLoading: nextCount > 0 || state.routeActive,
      loadKey: nextCount === 0 && !state.routeActive ? state.loadKey + 1 : state.loadKey,
    };
  }),

  startRouteLoad: () => set((state) => ({
    routeActive: true,
    isLoading: true,
    loadKey: state.loadKey + 1,
  })),

  finishRouteLoad: () => set((state) => ({
    routeActive: false,
    isLoading: state.activeCount > 0,
  })),
}));

export default useLoadingStore;
